use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CompiledRoleSet, DecisionReason,
    EnforcementMode, GrantStatus, HttpMethod, NormalizedPath, PathNormalizer, PermissionGrant,
    PolicySnapshot, PolicyVersion, RoleId, ServiceName, SubjectRef,
};
use shared_domain::Uuid;
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::token::FakeTokenRepository;

use super::{Authorization, GraphQlAuthorization, RequestAuthorizer, RouteRequest};
use crate::document_cache_fixtures::MapDocumentCache;
use crate::fixtures::{ROLE, USER, principal};
use crate::gateway::graphql_request::{
    BLOCKING_THRESHOLD_BYTES, GraphQlOperation, GraphQlRequestAnalyzer, ParseBudgetSettings,
    ParseObserver, ParseSite,
};

fn version() -> PolicyVersion {
    PolicyVersion::new(7).unwrap()
}

/// The typed entries of the `orders` service: `Query.orders` returns `Order`, whose fields are
/// scalars, and `Query.secret` is sensitive.
fn orders() -> Vec<CatalogueEntryState> {
    let field = |key: &str, return_type: &str, sensitive: bool| CatalogueEntryState {
        key: key.to_owned(),
        sensitive,
        audit_always: false,
        return_type: Some(return_type.to_owned()),
        possible_types: Vec::new(),
    };
    vec![
        field("gql:orders:Query.orders", "Order", false),
        field("gql:orders:Order.id", "ID", false),
        field("gql:orders:Order.total", "Int", false),
        field("gql:orders:Query.secret", "String", true),
    ]
}

/// The typed entries of the service `iam`: the root field `Query.roles` returns a scalar.
fn iam() -> Vec<CatalogueEntryState> {
    vec![CatalogueEntryState {
        key: "gql:iam:Query.roles".to_owned(),
        sensitive: false,
        audit_always: false,
        return_type: Some("String".to_owned()),
        possible_types: Vec::new(),
    }]
}

fn snapshot(grants: &[&str]) -> Arc<dyn PolicySnapshot> {
    let role = RoleId::parse(ROLE).unwrap();
    let set = CompiledRoleSet::compile(
        grants
            .iter()
            .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    Arc::new(
        GatewaySnapshot::at(version())
            .with_assignments(
                SubjectRef::user(Uuid::parse(USER).unwrap()),
                vec![AssignmentState {
                    role,
                    scope: AssignmentScope::Global,
                    expires_at_micros: None,
                }],
            )
            .with_role_set(role, set)
            .with_catalogue(ServiceName::new("orders").unwrap(), orders())
            .with_catalogue(ServiceName::new("iam").unwrap(), iam()),
    )
}

fn authorizer(budget: ParseBudgetSettings) -> RequestAuthorizer {
    authorizer_over(GraphQlRequestAnalyzer::new(
        Arc::new(MapDocumentCache::default()),
        budget,
    ))
}

fn authorizer_over(analyzer: GraphQlRequestAnalyzer) -> RequestAuthorizer {
    RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(FakeCommandBus::unregistered()),
    )
    .with_graphql(Arc::new(analyzer))
}

fn operations(documents: &[&str]) -> Vec<GraphQlOperation> {
    documents
        .iter()
        .map(|document| GraphQlOperation {
            document: (*document).to_owned(),
            operation_name: None,
        })
        .collect()
}

async fn decide(
    authorizer: &RequestAuthorizer,
    snapshot: &Arc<dyn PolicySnapshot>,
    service: &str,
    documents: &[&str],
) -> GraphQlAuthorization {
    decide_in(
        authorizer,
        snapshot,
        service,
        EnforcementMode::Enforce,
        documents,
    )
    .await
}

async fn decide_in(
    authorizer: &RequestAuthorizer,
    snapshot: &Arc<dyn PolicySnapshot>,
    service: &str,
    enforcement: EnforcementMode,
    documents: &[&str],
) -> GraphQlAuthorization {
    let service = ServiceName::new(service).unwrap();
    let path: NormalizedPath = PathNormalizer::normalize("/api/graphql").unwrap();
    let request = RouteRequest {
        snapshot,
        service: &service,
        enforcement,
        method: HttpMethod::Post,
        path: &path,
        request_id: Some("req-1"),
    };
    authorizer
        .authorize_graphql(&request, &principal(), &operations(documents))
        .await
}

fn authorization(decided: GraphQlAuthorization) -> Authorization {
    match decided {
        GraphQlAuthorization::Decided(traced) => traced.authorization,
        GraphQlAuthorization::RateLimited => panic!("rate limited"),
    }
}

const DOCUMENT: &str = "{ orders { id total } }";

#[tokio::test]
async fn a_subject_holding_every_coordinate_of_the_document_is_allowed() {
    let snapshot = snapshot(&[
        "gql:orders:Query.orders",
        "gql:orders:Order.id",
        "gql:orders:Order.total",
    ]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "orders",
        &[DOCUMENT],
    )
    .await;

    assert_eq!(authorization(decided), Authorization::Allowed(version()));
}

#[tokio::test]
async fn a_subject_holding_some_of_the_coordinates_is_denied_all_of_them() {
    let snapshot = snapshot(&["gql:orders:Query.orders", "gql:orders:Order.id"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "orders",
        &[DOCUMENT],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn one_denied_operation_of_a_batch_denies_the_batch() {
    let snapshot = snapshot(&["gql:orders:Query.orders", "gql:orders:Order.id"]);
    let allowed = "{ orders { id } }";

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "orders",
        &[allowed, allowed, DOCUMENT],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn a_wildcard_never_covers_a_sensitive_coordinate() {
    let snapshot = snapshot(&["gql:orders:*"]);
    let authorizer = authorizer(ParseBudgetSettings::default());

    let ordinary = decide(&authorizer, &snapshot, "orders", &[DOCUMENT]).await;
    let sensitive = decide(&authorizer, &snapshot, "orders", &["{ secret }"]).await;

    assert_eq!(authorization(ordinary), Authorization::Allowed(version()));
    assert_eq!(
        authorization(sensitive),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn an_introspection_query_needs_the_introspection_key() {
    let with = snapshot(&["gql:orders:__introspection"]);
    let without = snapshot(&["gql:orders:Query.orders"]);
    let authorizer = authorizer(ParseBudgetSettings::default());
    let query = "{ __schema { queryType { name } } }";

    let holder = decide(&authorizer, &with, "orders", &[query]).await;
    let other = decide(&authorizer, &without, "orders", &[query]).await;

    assert_eq!(authorization(holder), Authorization::Allowed(version()));
    assert_eq!(
        authorization(other),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn a_field_that_the_service_does_not_have_is_an_unknown_operation() {
    let snapshot = snapshot(&["gql:orders:*"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "orders",
        &["{ invoices { id } }"],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::UnknownOperation)
    );
}

#[tokio::test]
async fn a_service_without_a_catalogue_is_an_unknown_service() {
    let snapshot = snapshot(&["gql:orders:*"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "billing",
        &[DOCUMENT],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::UnknownService)
    );
}

#[tokio::test]
async fn a_route_in_audit_mode_forwards_what_enforce_mode_would_deny() {
    let snapshot = snapshot(&[]);

    let decided = decide_in(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "orders",
        EnforcementMode::Audit,
        &[DOCUMENT],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::WouldDeny(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn without_an_analyzer_the_request_fails_closed() {
    let snapshot = snapshot(&["gql:orders:*"]);
    let bare = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(FakeCommandBus::unregistered()),
    );

    let decided = decide(&bare, &snapshot, "orders", &[DOCUMENT]).await;

    assert_eq!(authorization(decided), Authorization::Unavailable);
}

#[tokio::test]
async fn a_subject_over_its_parse_budget_is_rate_limited() {
    let snapshot = snapshot(&["gql:orders:*"]);
    let authorizer = authorizer(ParseBudgetSettings {
        misses_per_second: 1,
        bytes_per_second: 1_048_576,
    });

    let first = decide(&authorizer, &snapshot, "orders", &["{ orders { id } }"]).await;
    let second = decide(&authorizer, &snapshot, "orders", &["{ orders { total } }"]).await;
    let cached = decide(&authorizer, &snapshot, "orders", &["{ orders { id } }"]).await;

    assert_eq!(authorization(first), Authorization::Allowed(version()));
    assert_eq!(second, GraphQlAuthorization::RateLimited);
    assert_eq!(authorization(cached), Authorization::Allowed(version()));
}

#[tokio::test]
async fn a_subject_holding_the_root_field_key_may_query_iam() {
    let snapshot = snapshot(&["gql:iam:Query.roles"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "iam",
        &["{ roles }"],
    )
    .await;

    assert_eq!(authorization(decided), Authorization::Allowed(version()));
}

#[tokio::test]
async fn a_subject_without_the_root_field_key_is_denied_on_iam() {
    let snapshot = snapshot(&["gql:orders:*"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "iam",
        &["{ roles }"],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn an_introspection_query_of_iam_has_no_rule_and_is_denied() {
    let snapshot = snapshot(&["gql:iam:*", "gql:iam:__introspection"]);

    let decided = decide(
        &authorizer(ParseBudgetSettings::default()),
        &snapshot,
        "iam",
        &["{ __schema { queryType { name } } }"],
    )
    .await;

    assert_eq!(
        authorization(decided),
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[derive(Debug)]
struct Panicking;

impl ParseObserver for Panicking {
    fn parsed(&self, _site: ParseSite, _bytes: usize) {
        panic!("the parse of this document fails");
    }
}

#[tokio::test]
async fn an_analysis_that_does_not_finish_leaves_the_request_unavailable() {
    let snapshot = snapshot(&["gql:orders:*"]);
    let analyzer = GraphQlRequestAnalyzer::new(
        Arc::new(MapDocumentCache::default()),
        ParseBudgetSettings::default(),
    )
    .with_observer(Arc::new(Panicking));
    let padding = " ".repeat(BLOCKING_THRESHOLD_BYTES * 2);
    let large = format!("{{ orders {{ id }} }}{padding}");

    let decided = decide(&authorizer_over(analyzer), &snapshot, "orders", &[&large]).await;

    assert_eq!(authorization(decided), Authorization::Unavailable);
}
