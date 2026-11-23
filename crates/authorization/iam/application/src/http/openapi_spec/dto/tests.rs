use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, HttpMethod, OpenApiSpecContent, OpenApiSpecParts, PathTemplate,
    PermissionFlags, RemovedRestGrant, RestFlagDowngrade, RestOperation, RestOperationKey,
    RestOperationSet, RestSpecDiff, RestWildcardGain, RoleId, ServiceName, SpecId, SpecStatus,
    WildcardPattern,
};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;
use validator::Validate as _;

use super::{
    GetOpenApiSpecParams, ListOpenApiSpecsParams, LoadOpenApiSpecRequest, OpenApiSpecPageResponse,
    OpenApiSpecResponse, OpenApiSpecSummaryResponse, OperationFlagDowngradeResponse,
    OperationFlagsResponse, OperationWildcardGainResponse, RemovedOperationGrantResponse,
    RestSpecDiffResponse,
};
use crate::error::IamError;
use crate::query::get_openapi_spec_diff::OpenApiSpecView;
use crate::query::get_openapi_specs::{GetOpenApiSpecsQuery, OpenApiSpecPage, OpenApiSpecSummary};

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f11-1234567890ad";
const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn key(method: HttpMethod, path: &str) -> RestOperationKey {
    RestOperationKey {
        method,
        template: PathTemplate::from_openapi_path(path).unwrap(),
    }
}

fn request(service: &str, document: &str) -> LoadOpenApiSpecRequest {
    LoadOpenApiSpecRequest {
        service: service.to_owned(),
        document: document.to_owned(),
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn view(status: SpecStatus, activated: Option<SystemTime>) -> OpenApiSpecView {
    let mut operations = RestOperationSet::new();
    operations
        .insert(RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path("/invoices").unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    let diff = RestSpecDiff::compute(&billing(), &operations, &RestOperationSet::new(), &[]);
    OpenApiSpecView {
        spec: OpenApiSpecParts {
            id: SpecId::parse(SPEC).unwrap(),
            content: OpenApiSpecContent {
                service: billing(),
                content_hash: ContentHash::new(&[0xab; 32]).unwrap(),
                operations,
            },
            status,
            uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
            created_at: at(86_400),
            activated_at: activated,
            retired_at: None,
        },
        operation_count: 1,
        diff,
    }
}

#[test]
fn a_request_with_a_service_and_a_document_is_valid() {
    assert!(request("billing", "{}").validate().is_ok());
}

#[test]
fn an_empty_service_or_document_and_a_service_over_63_characters_are_invalid() {
    assert!(request("", "{}").validate().is_err());
    assert!(request("billing", "").validate().is_err());
    assert!(request(&"a".repeat(64), "{}").validate().is_err());
    assert!(request(&"a".repeat(63), "{}").validate().is_ok());
}

#[test]
fn a_request_refuses_unknown_fields() {
    let parsed = serde_json::from_value::<LoadOpenApiSpecRequest>(
        json!({"service": "billing", "document": "{}", "extra": 1}),
    );

    assert!(parsed.is_err());
}

#[test]
fn the_debug_output_of_a_request_does_not_show_the_document() {
    let text = format!("{:?}", request("billing", "{\"secret\":true}"));

    assert!(text.contains("billing"));
    assert!(!text.contains("secret"));
}

#[test]
fn flags_are_two_booleans() {
    let flags = PermissionFlags::NONE.with_audit_always();

    assert_eq!(
        OperationFlagsResponse::from(flags),
        OperationFlagsResponse {
            sensitive: false,
            audit_always: true,
        }
    );
}

#[test]
fn a_draft_is_rendered_without_activation_times() {
    let response = OpenApiSpecResponse::from(&view(SpecStatus::Draft, None));

    assert_eq!(response.id, SPEC);
    assert_eq!(response.service, "billing");
    assert_eq!(response.content_hash, "ab".repeat(32));
    assert_eq!(response.status, "draft");
    assert_eq!(response.uploaded_by, format!("user:{USER}"));
    assert_eq!(response.created_at, "1970-01-02T00:00:00.000000Z");
    assert_eq!(response.activated_at, None);
    assert_eq!(response.retired_at, None);
    assert_eq!(response.operation_count, 1);
    assert_eq!(response.diff.added, ["GET /invoices"]);
    let value = serde_json::to_value(&response).unwrap();
    assert!(value.get("activatedAt").is_none());
    assert!(value.get("retiredAt").is_none());
    assert_eq!(value["contentHash"], "ab".repeat(32));
    assert_eq!(value["operationCount"], 1);
}

#[test]
fn an_active_version_is_rendered_with_its_activation_time() {
    let response = OpenApiSpecResponse::from(&view(SpecStatus::Active, Some(at(172_800))));

    assert_eq!(response.status, "active");
    assert_eq!(
        response.activated_at.as_deref(),
        Some("1970-01-03T00:00:00.000000Z")
    );
}

#[test]
fn an_empty_diff_is_rendered_with_empty_lists() {
    let diff = RestSpecDiff::compute(
        &billing(),
        &RestOperationSet::new(),
        &RestOperationSet::new(),
        &[],
    );

    assert_eq!(
        RestSpecDiffResponse::from(&diff),
        RestSpecDiffResponse {
            added: vec![],
            removed: vec![],
            removed_grants: vec![],
            wildcard_gains: vec![],
            flag_downgrades: vec![],
        }
    );
}

#[test]
fn the_parts_of_a_diff_are_rendered_with_operation_texts() {
    let role = RoleId::parse(ROLE).unwrap();
    let removed = RemovedRestGrant {
        operation: key(HttpMethod::Post, "/invoices/{id}/pay"),
        roles: vec![role],
    };
    assert_eq!(
        RemovedOperationGrantResponse::from(&removed),
        RemovedOperationGrantResponse {
            operation: "POST /invoices/{}/pay".to_owned(),
            roles: vec![ROLE.to_owned()],
        }
    );
    let gain = RestWildcardGain {
        role,
        pattern: WildcardPattern::parse("rest:billing:GET *").unwrap(),
        operations: vec![key(HttpMethod::Get, "/orders")],
    };
    assert_eq!(
        OperationWildcardGainResponse::from(&gain),
        OperationWildcardGainResponse {
            role: ROLE.to_owned(),
            pattern: "rest:billing:GET *".to_owned(),
            operations: vec!["GET /orders".to_owned()],
        }
    );
    let downgrade = RestFlagDowngrade {
        operation: key(HttpMethod::Post, "/invoices/{id}/pay"),
        before: PermissionFlags::NONE.with_sensitive(),
        after: PermissionFlags::NONE,
    };
    assert_eq!(
        OperationFlagDowngradeResponse::from(&downgrade),
        OperationFlagDowngradeResponse {
            operation: "POST /invoices/{}/pay".to_owned(),
            before: OperationFlagsResponse {
                sensitive: true,
                audit_always: false,
            },
            after: OperationFlagsResponse {
                sensitive: false,
                audit_always: false,
            },
        }
    );
}

fn summary(
    status: SpecStatus,
    activated: Option<SystemTime>,
    document: Option<&str>,
) -> OpenApiSpecSummary {
    let view = view(status, activated);
    OpenApiSpecSummary {
        spec: view.spec,
        operation_count: view.operation_count,
        document: document.map(str::to_owned),
    }
}

#[test]
fn a_summary_response_carries_the_state_the_count_and_the_requested_document() {
    let response = OpenApiSpecSummaryResponse::from(summary(
        SpecStatus::Active,
        Some(at(90_000)),
        Some("{\"openapi\":\"3.1.0\"}"),
    ));

    assert_eq!(response.id, SPEC);
    assert_eq!(response.service, "billing");
    assert_eq!(response.content_hash, "ab".repeat(32));
    assert_eq!(response.status, "active");
    assert_eq!(response.uploaded_by, format!("user:{USER}"));
    assert_eq!(response.created_at, "1970-01-02T00:00:00.000000Z");
    assert_eq!(
        response.activated_at.as_deref(),
        Some("1970-01-02T01:00:00.000000Z")
    );
    assert_eq!(response.retired_at, None);
    assert_eq!(response.operation_count, 1);
    assert_eq!(
        response.document.as_deref(),
        Some("{\"openapi\":\"3.1.0\"}")
    );
}

#[test]
fn a_summary_response_leaves_out_what_a_draft_does_not_have() {
    let body = serde_json::to_value(OpenApiSpecSummaryResponse::from(summary(
        SpecStatus::Draft,
        None,
        None,
    )))
    .unwrap();

    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["operationCount"], json!(1));
    assert!(body.get("activatedAt").is_none());
    assert!(body.get("retiredAt").is_none());
    assert!(body.get("document").is_none());
}

#[test]
fn a_page_response_lists_its_items_and_names_the_cursor_of_the_next_page() {
    let next = SpecId::parse(SPEC).unwrap();
    let page = OpenApiSpecPageResponse::from(OpenApiSpecPage {
        specs: vec![summary(SpecStatus::Draft, None, None)],
        next_after: Some(next),
    });
    let last = OpenApiSpecPageResponse::from(OpenApiSpecPage {
        specs: Vec::new(),
        next_after: None,
    });

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some(SPEC));
    assert_eq!(last.items, Vec::new());
    assert_eq!(last.next_cursor, None);
    let body = serde_json::to_value(&last).unwrap();
    assert!(body.get("nextCursor").is_none());
}

fn params() -> ListOpenApiSpecsParams {
    ListOpenApiSpecsParams::default()
}

fn violations(error: IamError) -> Vec<(String, String)> {
    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| (violation.property_path, violation.code))
        .collect()
}

#[test]
fn the_list_parameters_default_to_the_first_page_of_thirty_without_the_document() {
    let query = params().into_query().unwrap();

    assert_eq!(
        query,
        GetOpenApiSpecsQuery {
            limit: 30,
            after: None,
            service: None,
            status: None,
            include_document: false,
        }
    );
}

#[test]
fn the_list_parameters_become_the_query_filters() {
    let query = ListOpenApiSpecsParams {
        limit: 5,
        after: Some(SPEC.to_owned()),
        service: Some("billing".to_owned()),
        status: Some("retired".to_owned()),
        include_document: true,
    }
    .into_query()
    .unwrap();

    assert_eq!(
        query,
        GetOpenApiSpecsQuery {
            limit: 5,
            after: Some(SpecId::parse(SPEC).unwrap()),
            service: Some(billing()),
            status: Some(SpecStatus::Retired),
            include_document: true,
        }
    );
}

#[rstest]
#[case::zero(0, false)]
#[case::one(1, true)]
#[case::hundred(100, true)]
#[case::over(101, false)]
#[case::negative(-1, false)]
fn the_limit_is_between_one_and_one_hundred(#[case] limit: i32, #[case] valid: bool) {
    let parameters = ListOpenApiSpecsParams { limit, ..params() };

    assert_eq!(parameters.validate().is_ok(), valid);
}

#[test]
fn the_service_filter_has_at_most_63_characters() {
    let long = ListOpenApiSpecsParams {
        service: Some("a".repeat(64)),
        ..params()
    };
    let longest = ListOpenApiSpecsParams {
        service: Some("a".repeat(63)),
        ..params()
    };

    assert!(long.validate().is_err());
    assert!(longest.validate().is_ok());
}

#[test]
fn every_invalid_filter_is_a_violation_of_its_own_parameter() {
    let error = ListOpenApiSpecsParams {
        after: Some("not-a-uuid".to_owned()),
        service: Some("Not A Service".to_owned()),
        status: Some("pending".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [
            ("after".to_owned(), "uuid".to_owned()),
            ("service".to_owned(), "pattern".to_owned()),
            ("status".to_owned(), "choice".to_owned()),
        ]
    );
}

#[test]
fn a_single_invalid_status_is_one_violation() {
    let error = ListOpenApiSpecsParams {
        status: Some("pending".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [("status".to_owned(), "choice".to_owned())]
    );
}

#[test]
fn the_read_parameters_default_to_no_document_and_refuse_unknown_members() {
    assert!(!GetOpenApiSpecParams::default().include_document);
    assert!(GetOpenApiSpecParams::default().validate().is_ok());
    let parsed = serde_json::from_value::<GetOpenApiSpecParams>(json!({"includeDocument": true}));
    let unknown = serde_json::from_value::<GetOpenApiSpecParams>(json!({"document": true}));

    assert!(parsed.unwrap().include_document);
    assert!(unknown.is_err());
}
