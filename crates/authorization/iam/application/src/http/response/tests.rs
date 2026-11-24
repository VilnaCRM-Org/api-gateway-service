use axum::http::StatusCode;
use axum::http::header::{ETAG, LOCATION};
use axum::response::IntoResponse as _;
use iam_domain::{
    ActorRef, AuditTarget, ChangeId, ChangeReceipt, EntityVersion, PolicyVersion,
    PropagationOutcome,
};
use shared_domain::Uuid;

use super::{
    IAM_POLICY_OFFSET, IAM_POLICY_VERSION, IAM_PROPAGATION_STATUS, change_headers, created_headers,
    etag, write_status,
};

fn receipt(policy_version: Option<i64>) -> ChangeReceipt {
    ChangeReceipt::new(
        ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap(),
        ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()),
        AuditTarget::new("role", "0190f2a8-7b3c-7d4e-8f00-0000000000aa").unwrap(),
        EntityVersion::new(4).unwrap(),
        policy_version.map(|value| PolicyVersion::new(value).unwrap()),
    )
}

fn header(response: &axum::response::Response, name: &axum::http::HeaderName) -> Vec<String> {
    response
        .headers()
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_policy_version_header_is_named_like_the_specification() {
    assert_eq!(IAM_POLICY_VERSION.as_str(), "iam-policy-version");
}

#[test]
fn the_etag_of_a_version_is_the_quoted_number() {
    assert_eq!(etag(EntityVersion::new(1).unwrap()), "\"1\"");
    assert_eq!(
        etag(EntityVersion::new(i64::MAX).unwrap()),
        "\"9223372036854775807\""
    );
}

#[test]
fn a_change_that_affects_decisions_sets_the_etag_and_the_policy_version() {
    let response = (StatusCode::OK, change_headers(&receipt(Some(17)))).into_response();

    assert_eq!(header(&response, &ETAG), ["\"4\""]);
    assert_eq!(header(&response, &IAM_POLICY_VERSION), ["17"]);
    assert_eq!(header(&response, &LOCATION), Vec::<String>::new());
}

#[test]
fn a_change_that_does_not_affect_decisions_sets_the_etag_only() {
    let response = (StatusCode::OK, change_headers(&receipt(None))).into_response();

    assert_eq!(header(&response, &ETAG), ["\"4\""]);
    assert_eq!(header(&response, &IAM_POLICY_VERSION), Vec::<String>::new());
}

#[test]
fn a_create_also_sets_the_location_of_the_target_under_its_collection() {
    let response = (
        StatusCode::CREATED,
        created_headers(&receipt(Some(0)), "/api/roles"),
    )
        .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(header(&response, &ETAG), ["\"4\""]);
    assert_eq!(header(&response, &IAM_POLICY_VERSION), ["0"]);
    assert_eq!(
        header(&response, &LOCATION),
        ["/api/roles/0190f2a8-7b3c-7d4e-8f00-0000000000aa"]
    );
}

#[test]
fn the_offset_and_status_headers_are_named_like_the_specification() {
    assert_eq!(IAM_POLICY_OFFSET.as_str(), "iam-policy-offset");
    assert_eq!(IAM_PROPAGATION_STATUS.as_str(), "iam-propagation-status");
}

#[test]
fn a_published_write_carries_the_stored_offset_and_keeps_its_status() {
    let published =
        receipt(Some(17)).with_propagation(PropagationOutcome::Published { offset: 99 });

    let response = (
        write_status(&published, StatusCode::CREATED),
        change_headers(&published),
    )
        .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(header(&response, &IAM_POLICY_VERSION), ["17"]);
    assert_eq!(header(&response, &IAM_POLICY_OFFSET), ["99"]);
    assert_eq!(
        header(&response, &IAM_PROPAGATION_STATUS),
        Vec::<String>::new()
    );
}

#[test]
fn a_committed_write_that_was_not_acknowledged_is_accepted_with_its_status() {
    let pending = receipt(Some(17)).with_propagation(PropagationOutcome::CommittedPending);

    let response = (
        write_status(&pending, StatusCode::OK),
        change_headers(&pending),
    )
        .into_response();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(header(&response, &IAM_POLICY_VERSION), ["17"]);
    assert_eq!(
        header(&response, &IAM_PROPAGATION_STATUS),
        ["committed_pending_propagation"]
    );
    assert_eq!(header(&response, &IAM_POLICY_OFFSET), Vec::<String>::new());
}

#[test]
fn a_write_without_an_outcome_carries_no_offset_and_keeps_its_status() {
    let plain = receipt(None);

    let response = (write_status(&plain, StatusCode::OK), change_headers(&plain)).into_response();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, &IAM_POLICY_OFFSET), Vec::<String>::new());
}
