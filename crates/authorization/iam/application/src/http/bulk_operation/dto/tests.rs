//! Tests of the wire shapes of the bulk operations.

use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, BulkKind, BulkOperationId, BulkOperationParts, BulkStatus, PolicyVersion,
};

use super::{BulkOperationPageResponse, BulkOperationResponse, ListBulkOperationsParams};
use crate::bulk_operation_fixtures::uuid;
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::list_bulk_operations::BulkOperationPage;

const REQUESTER: &str = "user:7f0cdd0e-6c1a-4a3b-9f7e-0b8e8f5f5f01";

fn parts(id: u64, status: BulkStatus) -> BulkOperationParts {
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap();
    BulkOperationParts {
        id: BulkOperationId::from_uuid(uuid(id)),
        kind: BulkKind::RoleDeletion,
        status,
        total_records: 2_500,
        applied_records: 1_000,
        first_version: PolicyVersion::new(4).ok(),
        last_version: PolicyVersion::new(4).ok(),
        requester: ActorRef::parse(REQUESTER).unwrap(),
        error: None,
        created_at: at,
        updated_at: at,
    }
}

#[test]
fn a_response_carries_kind_status_progress_versions_and_requester() {
    let response = BulkOperationResponse::from(parts(7, BulkStatus::Running));

    assert_eq!(response.kind, "role_deletion");
    assert_eq!(response.status, "running");
    assert_eq!(response.total_records, 2_500);
    assert_eq!(response.applied_records, 1_000);
    assert_eq!(response.first_version, Some(4));
    assert_eq!(response.last_version, Some(4));
    assert_eq!(response.requester, REQUESTER);
    assert!(response.propagation.is_none());
}

#[test]
fn the_propagation_is_null_and_absent_members_are_left_out() {
    let mut stored = parts(7, BulkStatus::Pending);
    stored.first_version = None;
    stored.last_version = None;
    stored.applied_records = 0;

    let json = serde_json::to_value(BulkOperationResponse::from(stored)).unwrap();

    assert_eq!(json["propagation"], serde_json::Value::Null);
    assert!(json.get("firstVersion").is_none());
    assert!(json.get("lastVersion").is_none());
    assert!(json.get("error").is_none());
    assert_eq!(json["totalRecords"], 2_500);
}

#[test]
fn a_failed_operation_carries_its_error() {
    let mut stored = parts(7, BulkStatus::Failed);
    stored.error = Some("the plan is gone".to_owned());

    let response = BulkOperationResponse::from(stored);

    assert_eq!(response.status, "failed");
    assert_eq!(response.error.as_deref(), Some("the plan is gone"));
}

#[test]
fn a_page_names_the_cursor_of_the_next_page() {
    let next = BulkOperationId::from_uuid(uuid(9));
    let page = BulkOperationPage {
        operations: vec![parts(8, BulkStatus::Completed)],
        next_after: Some(next),
    };

    let response = BulkOperationPageResponse::from(page);

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.next_cursor, Some(next.to_string()));
}

#[test]
fn the_default_parameters_ask_for_the_first_page_of_the_default_size() {
    let query = ListBulkOperationsParams::default().into_query().unwrap();

    assert_eq!(query.limit, DEFAULT_PAGE_SIZE.unsigned_abs());
    assert_eq!(query.after, None);
}

#[test]
fn a_cursor_that_is_not_a_uuid_is_a_violation_of_after() {
    let params = ListBulkOperationsParams {
        after: Some("not-a-uuid".to_owned()),
        ..ListBulkOperationsParams::default()
    };

    let Err(IamError::Invalid(violations)) = params.into_query() else {
        panic!("a cursor that is not a UUID must be refused");
    };

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "after");
}

#[test]
fn a_cursor_is_parsed_into_the_query() {
    let id = uuid(5);
    let params = ListBulkOperationsParams {
        after: Some(id.to_string()),
        limit: 10,
    };

    let query = params.into_query().unwrap();

    assert_eq!(query.limit, 10);
    assert_eq!(query.after, Some(BulkOperationId::from_uuid(id)));
}
