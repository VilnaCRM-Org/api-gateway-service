use iam_domain::{
    EnforcementMode, EntityVersion, HttpMethod, RatePolicyId, RetryPolicy, RouteFlag, RouteId,
};
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{
    CorsPolicyDto, CreateRouteRequest, EnforcementDto, HttpMethodDto, ListRoutesParams,
    RetryPolicyDto, RoutePageResponse, RouteResponse, UpdateRouteRequest,
    delete_route_canonical_form,
};
use crate::command::update_route::{CorsChange, RoutePatch};
use crate::error::IamError;
use crate::query::list_routes::RoutePage;
use crate::route_fixtures::{ROUTE, UPSTREAM, route, route_id};

const POLICY: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ae";

fn create_request() -> CreateRouteRequest {
    serde_json::from_value(json!({
        "host": "app.example.test",
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
    }))
    .unwrap()
}

#[rstest]
#[case(HttpMethodDto::Get, HttpMethod::Get)]
#[case(HttpMethodDto::Head, HttpMethod::Head)]
#[case(HttpMethodDto::Post, HttpMethod::Post)]
#[case(HttpMethodDto::Put, HttpMethod::Put)]
#[case(HttpMethodDto::Patch, HttpMethod::Patch)]
#[case(HttpMethodDto::Delete, HttpMethod::Delete)]
#[case(HttpMethodDto::Options, HttpMethod::Options)]
fn the_wire_method_and_the_domain_method_convert_both_ways(
    #[case] wire: HttpMethodDto,
    #[case] domain: HttpMethod,
) {
    assert_eq!(HttpMethod::from(wire), domain);
    assert_eq!(HttpMethodDto::from(domain), wire);
}

#[test]
fn the_enforcement_and_the_retry_policy_convert_both_ways() {
    assert_eq!(
        EnforcementMode::from(EnforcementDto::Audit),
        EnforcementMode::Audit
    );
    assert_eq!(
        EnforcementDto::from(EnforcementMode::Enforce),
        EnforcementDto::Enforce
    );
    assert_eq!(
        RetryPolicy::from(RetryPolicyDto::Idempotent),
        RetryPolicy::Idempotent
    );
    assert_eq!(
        RetryPolicyDto::from(RetryPolicy::None),
        RetryPolicyDto::None
    );
}

#[test]
fn a_creation_without_the_optional_members_takes_the_defaults() {
    let draft = create_request().into_draft().unwrap();

    assert!(!draft.flags.anonymous());
    assert!(!draft.flags.graphql());
    assert!(!draft.flags.streaming());
    assert_eq!(draft.enforcement, EnforcementMode::Enforce);
    assert_eq!(draft.body_limit, 1_048_576);
    assert_eq!(draft.request_timeout_ms, 30_000);
    assert_eq!(draft.idle_timeout_ms, 60_000);
    assert_eq!(draft.retry, RetryPolicy::None);
    assert_eq!(draft.rate_policies, Vec::new());
    assert_eq!(draft.cors, None);
    assert!(create_request().validate().is_ok());
}

#[test]
fn a_creation_with_every_member_becomes_a_draft_with_every_member() {
    let request: CreateRouteRequest = serde_json::from_value(json!({
        "host": "app.example.test",
        "methods": ["GET", "PATCH"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": true,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 2048,
        "requestTimeoutMs": 1000,
        "idleTimeoutMs": 2000,
        "retryPolicy": "idempotent",
        "ratePolicyIds": [POLICY],
        "cors": {"origins": ["https://app.example.test"], "methods": ["GET"], "headers": ["x-a"], "allowCredentials": true, "maxAgeSeconds": 60},
    }))
    .unwrap();

    let draft = request.into_draft().unwrap();

    assert_eq!(draft.methods, [HttpMethod::Get, HttpMethod::Patch]);
    assert!(draft.flags.has(RouteFlag::Graphql));
    assert!(draft.flags.has(RouteFlag::Streaming));
    assert!(draft.flags.has(RouteFlag::Anonymous));
    assert_eq!(draft.enforcement, EnforcementMode::Audit);
    assert_eq!(draft.retry, RetryPolicy::Idempotent);
    assert_eq!(draft.rate_policies, [RatePolicyId::parse(POLICY).unwrap()]);
    let cors = draft.cors.unwrap();
    assert!(cors.allow_credentials);
    assert_eq!(cors.max_age_seconds, 60);
}

#[test]
fn a_cors_policy_without_the_optional_members_takes_the_defaults() {
    let cors: CorsPolicyDto =
        serde_json::from_value(json!({"origins": ["https://app.example.test"]})).unwrap();

    assert_eq!(cors.methods, Vec::new());
    assert_eq!(cors.headers, Vec::<String>::new());
    assert!(!cors.allow_credentials);
    assert_eq!(cors.max_age_seconds, 600);
}

#[rstest]
#[case::upstream("upstreamId", "upstreamId")]
#[case::rate_policy("ratePolicyIds", "ratePolicyIds")]
fn an_identifier_that_is_not_a_uuid_is_a_violation_of_its_property(
    #[case] member: &str,
    #[case] expected: &str,
) {
    let mut body = json!({
        "host": "app.example.test",
        "methods": ["GET"],
        "pathPattern": "/api/orders/{id}",
        "service": "core",
        "upstreamId": UPSTREAM,
    });
    body[member] = if member == "ratePolicyIds" {
        json!(["nope"])
    } else {
        json!("nope")
    };
    let request: CreateRouteRequest = serde_json::from_value(body).unwrap();

    let error = request.into_draft().unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, expected);
    assert_eq!(violations[0].code, "uuid");
}

#[test]
fn the_canonical_form_of_a_creation_changes_with_every_field() {
    let first = create_request();
    let mut second = create_request();
    second.path_pattern = "/api/other".to_owned();

    assert!(first.canonical_form().starts_with("route.create:"));
    assert_ne!(first.canonical_form(), second.canonical_form());
    assert_eq!(first.canonical_form(), create_request().canonical_form());
}

#[test]
fn the_canonical_forms_of_an_update_and_a_deletion_name_the_route_and_the_version() {
    let request = UpdateRouteRequest {
        streaming: Some(true),
        ..UpdateRouteRequest::default()
    };
    let one = EntityVersion::new(1).unwrap();
    let two = EntityVersion::new(2).unwrap();
    let other = RouteId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890d1").unwrap();

    let update = request.canonical_form(route_id(), one);

    assert!(update.starts_with("route.update:"));
    assert!(update.contains(ROUTE));
    assert_ne!(update, request.canonical_form(route_id(), two));
    assert_ne!(update, request.canonical_form(other, one));
    let deletion = delete_route_canonical_form(route_id(), one);
    assert!(deletion.starts_with("route.delete:"));
    assert_ne!(deletion, delete_route_canonical_form(route_id(), two));
    assert_ne!(deletion, delete_route_canonical_form(other, one));
    assert_ne!(deletion, update);
}

#[test]
fn an_update_with_every_member_becomes_a_patch_with_every_member() {
    let request: UpdateRouteRequest = serde_json::from_value(json!({
        "host": "other.example.test",
        "methods": ["POST"],
        "pathPattern": "/api/other",
        "service": "payment",
        "upstreamId": UPSTREAM,
        "graphql": true,
        "streaming": false,
        "anonymous": true,
        "enforcement": "audit",
        "bodyLimitBytes": 10,
        "requestTimeoutMs": 11,
        "idleTimeoutMs": 12,
        "retryPolicy": "idempotent",
        "ratePolicyIds": [POLICY],
        "cors": {"origins": ["https://app.example.test"]},
    }))
    .unwrap();

    let patch = request.into_patch().unwrap();

    assert_eq!(patch.host.as_deref(), Some("other.example.test"));
    assert_eq!(patch.methods, Some(vec![HttpMethod::Post]));
    assert_eq!(patch.path_pattern.as_deref(), Some("/api/other"));
    assert_eq!(patch.service.as_deref(), Some("payment"));
    assert!(patch.upstream_id.is_some());
    assert_eq!(patch.graphql, Some(true));
    assert_eq!(patch.streaming, Some(false));
    assert_eq!(patch.anonymous, Some(true));
    assert_eq!(patch.enforcement, Some(EnforcementMode::Audit));
    assert_eq!(patch.body_limit, Some(10));
    assert_eq!(patch.request_timeout_ms, Some(11));
    assert_eq!(patch.idle_timeout_ms, Some(12));
    assert_eq!(patch.retry, Some(RetryPolicy::Idempotent));
    assert_eq!(patch.rate_policies.unwrap().len(), 1);
    assert!(matches!(patch.cors, CorsChange::Set(_)));
}

#[test]
fn an_empty_update_is_an_empty_patch_and_a_null_cors_removes_the_policy() {
    let empty: UpdateRouteRequest = serde_json::from_value(json!({})).unwrap();
    let removing: UpdateRouteRequest = serde_json::from_value(json!({"cors": null})).unwrap();

    assert_eq!(empty.into_patch().unwrap(), RoutePatch::default());
    assert_eq!(removing.into_patch().unwrap().cors, CorsChange::Remove);
}

#[test]
fn an_update_names_an_identifier_that_is_not_a_uuid_as_a_violation() {
    let upstream = UpdateRouteRequest {
        upstream_id: Some("nope".to_owned()),
        ..UpdateRouteRequest::default()
    };
    let policies = UpdateRouteRequest {
        rate_policy_ids: Some(vec!["nope".to_owned()]),
        ..UpdateRouteRequest::default()
    };

    assert!(matches!(upstream.into_patch(), Err(IamError::Invalid(_))));
    assert!(matches!(policies.into_patch(), Err(IamError::Invalid(_))));
}

#[test]
fn an_update_validates_the_length_of_the_names_it_carries() {
    let request = UpdateRouteRequest {
        host: Some(String::new()),
        ..UpdateRouteRequest::default()
    };

    assert!(request.validate().is_err());
    assert!(UpdateRouteRequest::default().validate().is_ok());
}

#[test]
fn a_stored_route_is_shown_with_every_field_in_the_names_of_the_wire() {
    let response = RouteResponse::from(route(3));

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "id": ROUTE,
            "host": "app.example.test",
            "methods": ["GET"],
            "pathPattern": "/api/orders/{id}",
            "service": "core",
            "upstreamId": UPSTREAM,
            "graphql": false,
            "streaming": false,
            "anonymous": false,
            "enforcement": "enforce",
            "bodyLimitBytes": 1_048_576,
            "requestTimeoutMs": 30_000,
            "idleTimeoutMs": 60_000,
            "retryPolicy": "none",
            "ratePolicyIds": [],
            "system": false,
            "version": 3,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:05:00.000000Z",
        })
    );
}

#[test]
fn a_route_with_a_cors_policy_shows_the_policy_unchanged() {
    let mut stored = route(1);
    let mut draft = test_support::route::route_draft(
        "app.example.test",
        "/api/orders/{id}",
        &[HttpMethod::Get],
        "core",
        crate::route_fixtures::upstream_id(),
    );
    draft.cors = Some(
        serde_json::from_value::<CorsPolicyDto>(json!({
            "origins": ["https://app.example.test"],
            "methods": ["GET"],
            "headers": ["content-type"],
            "allowCredentials": true,
            "maxAgeSeconds": 120,
        }))
        .unwrap()
        .into(),
    );
    stored.fields = iam_domain::RouteFields::new(&draft).unwrap();

    let value = serde_json::to_value(RouteResponse::from(stored)).unwrap();

    assert_eq!(
        value["cors"],
        json!({
            "origins": ["https://app.example.test"],
            "methods": ["GET"],
            "headers": ["content-type"],
            "allowCredentials": true,
            "maxAgeSeconds": 120,
        })
    );
}

#[test]
fn a_page_lists_its_items_and_names_the_cursor_only_when_another_page_follows() {
    let last = RoutePageResponse::from(RoutePage {
        routes: vec![route(1)],
        next_after: None,
    });
    let more = RoutePageResponse::from(RoutePage {
        routes: vec![route(1)],
        next_after: Some(route_id()),
    });

    assert_eq!(last.items.len(), 1);
    assert_eq!(last.next_cursor, None);
    assert_eq!(more.next_cursor.as_deref(), Some(ROUTE));
    assert_eq!(serde_json::to_value(&last).unwrap().get("nextCursor"), None);
}

#[test]
fn the_parameters_default_to_the_first_page_of_30_without_filters() {
    let params = ListRoutesParams::default();

    assert_eq!(params.limit, 30);
    assert!(params.validate().is_ok());
    let query = params.into_query().unwrap();
    assert_eq!(query.limit, 30);
    assert_eq!(query.host, None);
}

#[rstest]
#[case(0)]
#[case(-3)]
#[case(101)]
fn a_limit_outside_1_to_100_is_invalid(#[case] limit: i32) {
    let params = ListRoutesParams {
        limit,
        ..ListRoutesParams::default()
    };

    assert!(params.validate().is_err());
}

#[test]
fn the_filters_become_the_values_of_the_query() {
    let params = ListRoutesParams {
        limit: 5,
        after: Some(ROUTE.to_owned()),
        host: Some("app.example.test".to_owned()),
        upstream: Some(UPSTREAM.to_owned()),
        service: Some("core".to_owned()),
    };

    let query = params.into_query().unwrap();

    assert_eq!(query.after, Some(route_id()));
    assert_eq!(query.host.unwrap().as_str(), "app.example.test");
    assert_eq!(query.upstream.unwrap().to_string(), UPSTREAM);
    assert_eq!(query.service.unwrap().as_str(), "core");
}

#[rstest]
#[case::after(ListRoutesParams { after: Some("x".to_owned()), ..ListRoutesParams::default() }, "after")]
#[case::host(ListRoutesParams { host: Some("Bad Host".to_owned()), ..ListRoutesParams::default() }, "host")]
#[case::upstream(ListRoutesParams { upstream: Some("x".to_owned()), ..ListRoutesParams::default() }, "upstream")]
#[case::service(ListRoutesParams { service: Some("Bad Service".to_owned()), ..ListRoutesParams::default() }, "service")]
fn a_filter_that_is_not_valid_is_a_violation_of_its_parameter(
    #[case] params: ListRoutesParams,
    #[case] property: &str,
) {
    let error = params.into_query().unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, property);
}
