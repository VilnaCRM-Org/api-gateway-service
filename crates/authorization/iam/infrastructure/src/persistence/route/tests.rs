use std::time::{Duration, SystemTime};

use iam_domain::{
    EnforcementMode, EntityVersion, HttpMethod, RepositoryError, RetryPolicy, UpstreamId,
};
use rstest::rstest;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{RouteRow, cors_text, method_texts, methods_of, restore};

const ROUTE: &str = "0192f6a0-0000-7000-8000-0000000000a1";
const UPSTREAM: &str = "5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d";
const POLICY_ONE: &str = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";
const POLICY_TWO: &str = "7d4f1e3c-9f5b-4c8d-8e2f-3a4b5c6d7e8f";
const CORS: &str = r#"{"allowCredentials":true,"headers":["Authorization"],"maxAgeSeconds":600,"methods":["GET"],"origins":["https://app.example.com"]}"#;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn row() -> RouteRow {
    RouteRow {
        id: SqlUuid::parse_str(ROUTE).unwrap(),
        host: "api.example.com".to_owned(),
        methods: vec!["GET".to_owned(), "POST".to_owned()],
        path_pattern: "/users/{id}".to_owned(),
        service: "core".to_owned(),
        upstream_id: SqlUuid::parse_str(UPSTREAM).unwrap(),
        flags: vec![true, false, true],
        enforcement: "audit".to_owned(),
        body_limit: 1_048_576,
        request_timeout_ms: 30_000,
        idle_timeout_ms: 60_000,
        retry: "idempotent".to_owned(),
        cors: Some(CORS.to_owned()),
        system: true,
        version: 5,
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
        rate_policies: vec![
            SqlUuid::parse_str(POLICY_TWO).unwrap(),
            SqlUuid::parse_str(POLICY_ONE).unwrap(),
        ],
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column_and_its_rate_policies_in_order() {
    let parts = restore(row()).unwrap();
    let fields = &parts.fields;

    assert_eq!(parts.id.to_string(), ROUTE);
    assert_eq!(fields.host().as_str(), "api.example.com");
    assert_eq!(fields.methods(), [HttpMethod::Get, HttpMethod::Post]);
    assert_eq!(fields.path_pattern().as_str(), "/users/{id}");
    assert_eq!(fields.service().as_str(), "core");
    assert_eq!(fields.upstream_id(), UpstreamId::parse(UPSTREAM).unwrap());
    assert!(fields.flags().graphql() && fields.flags().anonymous() && !fields.flags().streaming());
    assert_eq!(fields.enforcement(), EnforcementMode::Audit);
    assert_eq!(fields.body_limit().bytes(), 1_048_576);
    assert_eq!(fields.timeouts().request_ms(), 30_000);
    assert_eq!(fields.timeouts().idle_ms(), 60_000);
    assert_eq!(fields.retry(), RetryPolicy::Idempotent);
    let policies: Vec<String> = fields
        .rate_policies()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(policies, [POLICY_TWO, POLICY_ONE]);
    let cors = fields.cors().unwrap();
    assert_eq!(cors.origins(), ["https://app.example.com"]);
    assert_eq!(cors.methods(), [HttpMethod::Get]);
    assert_eq!(cors.headers(), ["Authorization"]);
    assert!(cors.allow_credentials());
    assert_eq!(cors.max_age_seconds(), 600);
    assert!(parts.system);
    assert_eq!(parts.version, EntityVersion::new(5).unwrap());
    assert_eq!(parts.created_at, at(1_700_000_000));
    assert_eq!(parts.updated_at, at(1_700_000_100));
    assert_eq!(parts.deleted_at, None);
}

#[test]
fn a_row_without_cors_is_restored_without_a_cors_policy() {
    let parts = restore(RouteRow {
        cors: None,
        ..row()
    })
    .unwrap();

    assert_eq!(parts.fields.cors(), None);
}

#[rstest]
#[case::too_few_flags(RouteRow { flags: vec![true, false], ..row() })]
#[case::unknown_method(RouteRow { methods: vec!["FETCH".to_owned()], ..row() })]
#[case::unknown_enforcement(RouteRow { enforcement: "warn".to_owned(), ..row() })]
#[case::unknown_retry(RouteRow { retry: "always".to_owned(), ..row() })]
#[case::cors_not_json(RouteRow { cors: Some("nope".to_owned()), ..row() })]
#[case::invalid_host(RouteRow { host: "API.example.com".to_owned(), ..row() })]
#[case::zero_body_limit(RouteRow { body_limit: 0, ..row() })]
#[case::version_below_one(RouteRow { version: 0, ..row() })]
fn a_row_that_breaks_an_invariant_is_unavailable(#[case] row: RouteRow) {
    assert!(matches!(restore(row), Err(RepositoryError::Unavailable(_))));
}

#[test]
fn the_methods_of_a_route_are_stored_as_text_in_order() {
    let parts = restore(row()).unwrap();

    assert_eq!(method_texts(&parts), ["GET", "POST"]);
    assert_eq!(
        methods_of(&["PUT".to_owned(), "GET".to_owned()]).unwrap(),
        [HttpMethod::Put, HttpMethod::Get]
    );
}

#[test]
fn the_cors_policy_of_a_route_is_stored_as_its_canonical_json_when_it_has_one() {
    let with = restore(row()).unwrap();
    let without = restore(RouteRow {
        cors: None,
        ..row()
    })
    .unwrap();

    assert_eq!(cors_text(&with).as_deref(), Some(CORS));
    assert_eq!(cors_text(&without), None);
}
