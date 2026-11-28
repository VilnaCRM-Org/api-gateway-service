use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CompiledRoleSet, Credential,
    DecisionReason, EnforcementMode, GrantStatus, HttpMethod, NormalizedPath, PathNormalizer,
    PermissionGrant, PolicySnapshot, PolicyVersion, RoleId, ServiceName, SubjectRef,
};
use shared_domain::Uuid;
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::token::FakeTokenRepository;

use super::{OperationVerdict, SubscriptionAuthorizer};
use crate::document_cache_fixtures::MapDocumentCache;
use crate::fixtures::{ROLE, USER, principal};
use crate::gateway::graphql_request::{
    GraphQlOperation, GraphQlRequestAnalyzer, ParseBudgetSettings,
};
use crate::gateway::request_authorizer::{Authorization, RequestAuthorizer, RouteRequest};

fn version() -> PolicyVersion {
    PolicyVersion::new(7).unwrap()
}

fn field(key: &str, return_type: &str) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
        return_type: Some(return_type.to_owned()),
        possible_types: Vec::new(),
    }
}

/// The typed entries of the `orders` service: two subscriptions, a query and a mutation.
fn orders() -> Vec<CatalogueEntryState> {
    vec![
        field("gql:orders:Query.orders", "String"),
        field("gql:orders:Mutation.cancel", "String"),
        field("gql:orders:Subscription.orderUpdated", "String"),
        field("gql:orders:Subscription.paymentUpdated", "String"),
    ]
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
            .with_catalogue(ServiceName::new("orders").unwrap(), orders()),
    )
}

fn subscriptions(budget: ParseBudgetSettings) -> SubscriptionAuthorizer {
    let authorizer = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(FakeCommandBus::unregistered()),
    )
    .with_graphql(Arc::new(GraphQlRequestAnalyzer::new(
        Arc::new(MapDocumentCache::default()),
        budget,
    )));
    SubscriptionAuthorizer::new(Arc::new(authorizer))
}

fn operation(document: &str) -> GraphQlOperation {
    GraphQlOperation {
        document: document.to_owned(),
        operation_name: None,
    }
}

async fn decide(
    subscriptions: &SubscriptionAuthorizer,
    snapshot: &Arc<dyn PolicySnapshot>,
    enforcement: EnforcementMode,
    document: &str,
) -> OperationVerdict {
    let service = ServiceName::new("orders").unwrap();
    let path: NormalizedPath = PathNormalizer::normalize("/graphql").unwrap();
    let request = RouteRequest {
        snapshot,
        service: &service,
        enforcement,
        method: HttpMethod::Get,
        path: &path,
        request_id: None,
    };
    subscriptions
        .authorize_operation(&request, &principal(), &operation(document))
        .await
}

const ORDER_UPDATED: &str = "subscription { orderUpdated }";
const PAYMENT_UPDATED: &str = "subscription { paymentUpdated }";

#[test]
fn the_token_of_the_upgrade_request_wins_over_the_payload() {
    let credential = SubscriptionAuthorizer::connection_credential(
        Credential::new("from-the-request".to_owned()),
        Some("Bearer from-the-payload"),
    );

    assert_eq!(credential.expose(), "from-the-request");
}

#[test]
fn the_payload_is_read_only_when_the_upgrade_request_has_no_token() {
    let credential = SubscriptionAuthorizer::connection_credential(
        Credential::new("  ".to_owned()),
        Some("Bearer from-the-payload"),
    );

    assert_eq!(credential.expose(), "from-the-payload");
}

#[test]
fn a_payload_token_may_come_without_the_scheme() {
    let credential = SubscriptionAuthorizer::connection_credential(
        Credential::new(String::new()),
        Some(" raw "),
    );

    assert_eq!(credential.expose(), "raw");
}

#[test]
fn the_scheme_of_the_payload_token_is_matched_without_regard_to_case() {
    let credential = SubscriptionAuthorizer::connection_credential(
        Credential::new(String::new()),
        Some("bEaReR abc"),
    );

    assert_eq!(credential.expose(), "abc");
}

#[test]
fn a_connection_without_a_token_anywhere_has_a_blank_credential() {
    let none = SubscriptionAuthorizer::connection_credential(Credential::new(String::new()), None);
    let scheme_only = SubscriptionAuthorizer::connection_credential(
        Credential::new(String::new()),
        Some("Bearer"),
    );

    assert!(none.is_blank());
    assert!(scheme_only.is_blank());
}

#[tokio::test]
async fn a_subscription_whose_root_field_the_subject_holds_is_allowed_with_its_keys() {
    let snapshot = snapshot(&["gql:orders:Subscription.orderUpdated"]);

    let verdict = decide(
        &subscriptions(ParseBudgetSettings::default()),
        &snapshot,
        EnforcementMode::Enforce,
        ORDER_UPDATED,
    )
    .await;

    assert_eq!(
        verdict,
        OperationVerdict::Allowed {
            version: version(),
            keys: vec!["gql:orders:Subscription.orderUpdated".to_owned()],
        }
    );
}

#[tokio::test]
async fn a_subscription_whose_root_field_the_subject_lacks_is_forbidden() {
    let snapshot = snapshot(&["gql:orders:Subscription.orderUpdated"]);

    let verdict = decide(
        &subscriptions(ParseBudgetSettings::default()),
        &snapshot,
        EnforcementMode::Enforce,
        PAYMENT_UPDATED,
    )
    .await;

    assert_eq!(
        verdict,
        OperationVerdict::Forbidden(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn a_mutation_without_its_key_is_forbidden() {
    let snapshot = snapshot(&["gql:orders:Query.orders"]);

    let verdict = decide(
        &subscriptions(ParseBudgetSettings::default()),
        &snapshot,
        EnforcementMode::Enforce,
        "mutation { cancel }",
    )
    .await;

    assert_eq!(
        verdict,
        OperationVerdict::Forbidden(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn a_route_in_audit_mode_lets_a_denied_operation_run() {
    let snapshot = snapshot(&[]);

    let verdict = decide(
        &subscriptions(ParseBudgetSettings::default()),
        &snapshot,
        EnforcementMode::Audit,
        PAYMENT_UPDATED,
    )
    .await;

    assert!(matches!(verdict, OperationVerdict::Allowed { .. }));
}

#[tokio::test]
async fn a_document_the_service_does_not_define_is_forbidden() {
    let snapshot = snapshot(&["gql:orders:Query.orders"]);

    let verdict = decide(
        &subscriptions(ParseBudgetSettings::default()),
        &snapshot,
        EnforcementMode::Enforce,
        "subscription { invented }",
    )
    .await;

    assert!(matches!(verdict, OperationVerdict::Forbidden(_)));
}

#[tokio::test]
async fn a_subject_over_its_parse_budget_is_rate_limited() {
    let snapshot = snapshot(&["gql:orders:Subscription.orderUpdated"]);
    let subscriptions = subscriptions(ParseBudgetSettings {
        misses_per_second: 1,
        bytes_per_second: 1_048_576,
    });
    decide(
        &subscriptions,
        &snapshot,
        EnforcementMode::Enforce,
        ORDER_UPDATED,
    )
    .await;

    let verdict = decide(
        &subscriptions,
        &snapshot,
        EnforcementMode::Enforce,
        "subscription  { orderUpdated }",
    )
    .await;

    assert_eq!(verdict, OperationVerdict::RateLimited);
}

#[tokio::test]
async fn the_route_decision_is_the_decision_of_the_request_authorizer() {
    let snapshot = snapshot(&[]);
    let service = ServiceName::new("orders").unwrap();
    let path: NormalizedPath = PathNormalizer::normalize("/graphql").unwrap();
    let request = RouteRequest {
        snapshot: &snapshot,
        service: &service,
        enforcement: EnforcementMode::Enforce,
        method: HttpMethod::Get,
        path: &path,
        request_id: None,
    };

    let decided = subscriptions(ParseBudgetSettings::default())
        .authorize_route(&request, &principal())
        .await;

    assert!(matches!(decided.authorization, Authorization::Denied(_)));
}

#[tokio::test]
async fn an_authorizer_without_a_document_analyzer_cannot_decide_an_operation() {
    let authorizer = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        Arc::new(FakeCommandBus::unregistered()),
    );
    let subscriptions = SubscriptionAuthorizer::new(Arc::new(authorizer));
    let snapshot = snapshot(&["gql:orders:Subscription.orderUpdated"]);

    let verdict = decide(
        &subscriptions,
        &snapshot,
        EnforcementMode::Enforce,
        ORDER_UPDATED,
    )
    .await;

    assert_eq!(verdict, OperationVerdict::Unavailable);
}
