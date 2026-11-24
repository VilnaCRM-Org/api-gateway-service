use iam_domain::{
    EnforcementMode, HttpMethod, RatePolicyId, RetryPolicy, RouteFields, RouteFlag, RouteFlags,
};
use serde_json::json;
use test_support::route::route_draft;
use validator::Validate as _;

use super::{
    ApplyRouteConfigurationParams, ApplyRouteConfigurationRequest, RouteConfigurationDiffResponse,
    RouteConfigurationResponse, RouteDeclarationDto,
};
use crate::error::IamError;
use crate::http::route::dto::{EnforcementDto, HttpMethodDto, RetryPolicyDto};
use crate::route_configuration_fixtures::{configuration, declared, preview};
use crate::route_fixtures::{HOST, UPSTREAM, numbered_id, route_at, upstream_id};

const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn minimal() -> RouteDeclarationDto {
    serde_json::from_value(json!({
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
    }))
    .unwrap()
}

#[test]
fn a_declaration_has_the_defaults_of_a_created_route() {
    let declaration = minimal();

    assert_eq!(declaration.graphql, None);
    assert_eq!(declaration.streaming, None);
    assert_eq!(declaration.anonymous, None);
    assert_eq!(declaration.enforcement, EnforcementDto::Enforce);
    assert_eq!(declaration.body_limit_bytes, 1_048_576);
    assert_eq!(declaration.request_timeout_ms, 30_000);
    assert_eq!(declaration.idle_timeout_ms, 60_000);
    assert_eq!(declaration.retry_policy, RetryPolicyDto::None);
    assert_eq!(declaration.rate_policy_ids.len(), 0);
    assert_eq!(declaration.cors, None);
}

#[test]
fn a_declaration_becomes_a_draft_with_every_member() {
    let declaration: RouteDeclarationDto = serde_json::from_value(json!({
        "methods": ["GET", "POST"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": true,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 2048,
        "requestTimeoutMs": 5000,
        "idleTimeoutMs": 6000,
        "retryPolicy": "idempotent",
        "ratePolicyIds": [POLICY],
        "cors": { "origins": ["https://app.example.test"] },
    }))
    .unwrap();

    let draft = declaration.into_draft().unwrap();

    assert_eq!(draft.host, "");
    assert_eq!(draft.methods, [HttpMethod::Get, HttpMethod::Post]);
    assert_eq!(draft.path_pattern, "/api/orders/{id}");
    assert_eq!(draft.upstream_id, upstream_id());
    assert!(draft.flags.graphql());
    assert!(draft.flags.streaming());
    assert!(draft.flags.anonymous());
    assert_eq!(draft.enforcement, EnforcementMode::Audit);
    assert_eq!(draft.body_limit, 2048);
    assert_eq!(draft.request_timeout_ms, 5000);
    assert_eq!(draft.idle_timeout_ms, 6000);
    assert_eq!(draft.retry, RetryPolicy::Idempotent);
    assert_eq!(draft.rate_policies, [RatePolicyId::parse(POLICY).unwrap()]);
    assert_eq!(draft.cors.unwrap().origins, ["https://app.example.test"]);
}

#[test]
fn a_stored_route_becomes_the_declaration_that_the_operation_accepts() {
    let mut draft = route_draft(HOST, "/a", &[HttpMethod::Get], "core", upstream_id());
    draft.flags = RouteFlags::default().with(RouteFlag::Streaming, true);
    draft.rate_policies = vec![RatePolicyId::parse(POLICY).unwrap()];
    let mut stored = route_at(numbered_id(1), "/a", &[HttpMethod::Get], 3);
    stored.fields = RouteFields::new(&draft).unwrap();

    let declaration = RouteDeclarationDto::from(stored);

    assert_eq!(declaration.methods, [HttpMethodDto::Get]);
    assert_eq!(declaration.path_pattern, "/a");
    assert_eq!(declaration.upstream_id, UPSTREAM);
    assert_eq!(declaration.streaming, Some(true));
    assert_eq!(declaration.graphql, Some(false));
    assert_eq!(declaration.anonymous, Some(false));
    assert_eq!(declaration.rate_policy_ids, [POLICY]);
    assert_eq!(declaration.body_limit_bytes, 1_048_576);
    let round_trip = declaration.clone().into_draft().unwrap();
    assert_eq!(round_trip.path_pattern, "/a");
    let wire = serde_json::to_value(&declaration).unwrap();
    assert_eq!(wire.get("cors"), None);
    assert_eq!(wire["enforcement"], json!("enforce"));
}

#[test]
fn the_request_names_the_position_of_the_route_that_cannot_be_read() {
    let mut broken = minimal();
    broken.upstream_id = "nope".to_owned();
    let request = ApplyRouteConfigurationRequest {
        routes: vec![minimal(), broken],
    };

    let IamError::Invalid(violations) = request.into_drafts().unwrap_err() else {
        panic!("a validation failure expected");
    };

    assert_eq!(violations[0].property_path, "routes[1].upstreamId");
}

#[test]
fn the_request_becomes_one_draft_per_route() {
    let request = ApplyRouteConfigurationRequest {
        routes: vec![minimal(), minimal()],
    };

    assert!(request.validate().is_ok());
    assert_eq!(request.into_drafts().unwrap().len(), 2);
}

#[test]
fn a_dry_run_is_off_unless_asked_for() {
    assert!(!ApplyRouteConfigurationParams::default().dry_run);
    assert!(ApplyRouteConfigurationParams::default().validate().is_ok());
}

#[test]
fn the_configuration_response_carries_the_host_the_version_and_the_declarations() {
    let response = RouteConfigurationResponse::from(configuration());

    assert_eq!(response.host, HOST);
    assert_eq!(response.version, configuration().version.value());
    assert_eq!(response.routes.len(), 2);
    assert_eq!(response.routes[0].path_pattern, "/a");
}

#[test]
fn a_diff_response_lists_the_added_the_changed_with_their_fields_and_the_removed_routes() {
    let mut slower = route_draft(HOST, "/b", &[HttpMethod::Get], "core", upstream_id());
    slower.request_timeout_ms = 5_000;
    let slower = RouteFields::new(&slower).unwrap();
    let preview = preview(vec![slower, declared("/c")]);

    let response = RouteConfigurationDiffResponse::of(&preview, true, None);

    assert_eq!(response.host, HOST);
    assert!(response.dry_run);
    assert_eq!(response.version, preview.version.value());
    assert_eq!(response.route_count, 3);
    assert!(response.revocation);
    assert_eq!(response.unchanged, 0);
    assert_eq!(response.added.len(), 1);
    assert_eq!(response.added[0].path_pattern, "/c");
    assert_eq!(response.added[0].changed_fields.len(), 0);
    assert_eq!(response.changed.len(), 1);
    assert_eq!(response.changed[0].path_pattern, "/b");
    assert_eq!(response.changed[0].changed_fields, ["timeouts"]);
    assert_eq!(response.removed.len(), 1);
    assert_eq!(response.removed[0].path_pattern, "/a");
    let wire = serde_json::to_value(&response).unwrap();
    assert_eq!(wire["added"][0].get("changedFields"), None);
    assert_eq!(wire["changed"][0]["changedFields"], json!(["timeouts"]));
}

#[test]
fn an_applied_response_carries_the_version_after_the_change() {
    let preview = preview(vec![declared("/a"), declared("/b"), declared("/c")]);

    let response = RouteConfigurationDiffResponse::of(&preview, false, Some(42));

    assert!(!response.dry_run);
    assert_eq!(response.version, 42);
    assert!(!response.revocation);
    assert_eq!(response.unchanged, 2);
}
