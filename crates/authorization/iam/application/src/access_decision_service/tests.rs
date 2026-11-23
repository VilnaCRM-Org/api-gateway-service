use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    AccessCheck, AccessTarget, AccessToken, AccessTokenParts, AssignmentScope, CompiledRoleSet,
    Credential, Decision, DecisionId, DecisionOutcome, DecisionReason, GrantStatus, HttpMethod,
    PathTemplate, PermissionFlags, PermissionGrant, PermissionsTarget, PolicyReadRepository,
    RepositoryError, RestOperation, RestOperationSet, RestTarget, RoleAssignment, RoleId,
    ServiceCatalog, ServiceName, SessionId, SubjectId, SubjectPolicy, SubjectRef, TokenId,
    TokenIdentity, TokenRejection,
};
use rstest::rstest;
use shared_domain::{Uuid, UuidGenerator as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;

use super::AccessDecisionService;
use crate::service_catalog_loader::ServiceCatalogLoader;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(USER).unwrap())
}

fn identity() -> TokenIdentity {
    TokenIdentity::from(
        &AccessToken::new(AccessTokenParts {
            subject: SubjectId::User(Uuid::parse(USER).unwrap()),
            session: Some(SessionId::new("session-1").unwrap()),
            token_id: TokenId::new("jti-1").unwrap(),
            roles: vec!["ROLE_USER".to_owned()],
            issued_at: at(NOW - 60),
            expires_at: at(NOW + 840),
        })
        .with_audiences(vec!["vilnacrm-api".to_owned()]),
    )
}

fn service() -> ServiceName {
    ServiceName::new("orders").unwrap()
}

fn role() -> RoleId {
    RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap()
}

fn catalog() -> ServiceCatalog {
    let mut operations = RestOperationSet::new();
    operations
        .insert(RestOperation {
            method: HttpMethod::Get,
            template: PathTemplate::from_openapi_path("/api/orders/{id}").unwrap(),
            label: None,
            flags: PermissionFlags::NONE,
        })
        .unwrap();
    ServiceCatalog::new(
        service(),
        seeded_policy_epoch(),
        vec![operations],
        Vec::new(),
    )
}

fn policy_with(expires_at: Option<SystemTime>) -> SubjectPolicy {
    let grants = [(
        PermissionGrant::parse("rest:orders:GET /api/orders/{}").unwrap(),
        GrantStatus::Active,
    )];
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(
            role(),
            AssignmentScope::Global,
            expires_at,
        )],
        BTreeMap::from([(role(), CompiledRoleSet::compile(grants))]),
    )
}

fn repository(expires_at: Option<SystemTime>) -> FakePolicyReadRepository {
    FakePolicyReadRepository::new()
        .with_catalog(catalog())
        .with_subject(user(), policy_with(expires_at))
}

fn tokens() -> FakeTokenRepository {
    FakeTokenRepository::new().accepting("valid", identity())
}

fn service_over(
    tokens: FakeTokenRepository,
    policy: impl PolicyReadRepository + 'static,
) -> AccessDecisionService {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(policy);
    AccessDecisionService::new(
        Arc::new(tokens),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

fn rest_check(path: &str) -> AccessCheck {
    AccessCheck::new(
        service(),
        AccessTarget::Rest(RestTarget::new(HttpMethod::Get, path.to_owned())),
        None,
        None,
    )
}

fn keys_check(keys: &[&str]) -> AccessCheck {
    let keys = keys.iter().map(|&key| key.to_owned()).collect();
    AccessCheck::new(
        service(),
        AccessTarget::Permissions(PermissionsTarget::new(keys).unwrap()),
        None,
        None,
    )
}

async fn decide(
    service: &AccessDecisionService,
    raw: &str,
    check: &AccessCheck,
) -> DecisionOutcome {
    service
        .decide(&Credential::new(raw.to_owned()), check)
        .await
}

/// A policy repository that reads the catalogue but fails reading the policy of a subject.
#[derive(Debug)]
struct SubjectReadFailing(FakePolicyReadRepository);

#[async_trait]
impl PolicyReadRepository for SubjectReadFailing {
    async fn read_subject_policy(
        &self,
        _subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        Err(RepositoryError::Unavailable("subject read failed".into()))
    }

    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.0.read_service_catalog(service).await
    }
}

#[tokio::test]
async fn a_rest_check_of_a_held_operation_is_allowed_with_the_facts_of_the_decision() {
    let service = service_over(tokens(), repository(None));

    let outcome = decide(&service, "valid", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.decision(), Decision::Allow);
    assert_eq!(outcome.reason(), DecisionReason::Allowed);
    assert_eq!(outcome.denied(), Vec::<String>::new());
    assert_eq!(outcome.subject(), Some(&user()));
    assert_eq!(
        outcome.policy_version(),
        Some(seeded_policy_epoch().version())
    );
}

#[tokio::test]
async fn a_service_token_is_decided_on_the_policy_of_the_service_subject() {
    let caller = ServiceName::new("billing").unwrap();
    let identity = TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::Service(caller.clone()),
        session: None,
        token_id: TokenId::new("jti-service").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    }));
    let subject = SubjectRef::service(caller);
    let policy = FakePolicyReadRepository::new()
        .with_catalog(catalog())
        .with_subject(subject.clone(), policy_with(None));
    let service = service_over(
        FakeTokenRepository::new().accepting("service", identity),
        policy,
    );

    let outcome = decide(&service, "service", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.decision(), Decision::Allow);
    assert_eq!(outcome.subject(), Some(&subject));
}

#[tokio::test]
async fn every_decision_gets_a_new_identifier_from_the_generator() {
    let service = service_over(tokens(), repository(None));

    let first = decide(&service, "valid", &rest_check("/api/orders/42")).await;
    let second = decide(&service, "other", &rest_check("/api/orders/42")).await;

    assert_ne!(first.decision_id(), second.decision_id());
    assert_eq!(
        first.decision_id(),
        DecisionId::from_uuid(SequenceUuidGenerator::starting_at(1).generate())
    );
}

#[tokio::test]
async fn a_subject_without_the_key_is_denied_with_permission_missing() {
    let policy = FakePolicyReadRepository::new().with_catalog(catalog());
    let service = service_over(tokens(), policy);

    let outcome = decide(&service, "valid", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.reason(), DecisionReason::PermissionMissing);
    assert_eq!(outcome.denied(), ["rest:orders:GET /api/orders/{}"]);
}

#[tokio::test]
async fn an_assignment_that_expired_by_the_clock_does_not_allow() {
    let service = service_over(tokens(), repository(Some(at(NOW))));

    let outcome = decide(&service, "valid", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.reason(), DecisionReason::PermissionMissing);
}

#[rstest]
#[case(TokenRejection::Invalid, DecisionReason::TokenInvalid)]
#[case(TokenRejection::Expired, DecisionReason::TokenExpired)]
#[case(TokenRejection::Revoked, DecisionReason::TokenRevoked)]
#[tokio::test]
async fn a_refused_credential_is_denied_with_the_matching_token_reason(
    #[case] rejection: TokenRejection,
    #[case] reason: DecisionReason,
) {
    let tokens = FakeTokenRepository::new().rejecting("refused", rejection);
    let service = service_over(tokens, repository(None));

    let outcome = decide(&service, "refused", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), reason);
    assert_eq!(outcome.subject(), None);
    assert_eq!(outcome.policy_version(), None);
}

#[tokio::test]
async fn a_missing_credential_is_denied_with_token_missing() {
    let service = service_over(tokens(), repository(None));

    let outcome = decide(&service, "  ", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.reason(), DecisionReason::TokenMissing);
}

#[tokio::test]
async fn an_unregistered_credential_is_denied_with_token_invalid() {
    let service = service_over(tokens(), repository(None));

    let outcome = decide(&service, "forged", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.reason(), DecisionReason::TokenInvalid);
}

#[tokio::test]
async fn a_service_without_an_active_version_is_an_unknown_service() {
    let policy = FakePolicyReadRepository::new().with_subject(user(), policy_with(None));
    let service = service_over(tokens(), policy);

    let outcome = decide(&service, "valid", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.reason(), DecisionReason::UnknownService);
    assert_eq!(outcome.subject(), Some(&user()));
}

#[tokio::test]
async fn unknown_keys_are_denied_as_an_unknown_operation_and_listed() {
    let service = service_over(tokens(), repository(None));
    let check = keys_check(&[
        "rest:orders:GET /api/orders/{}",
        "rest:orders:GET /api/missing",
        "rest:billing:GET /api/orders/{}",
    ]);

    let outcome = decide(&service, "valid", &check).await;

    assert_eq!(outcome.reason(), DecisionReason::UnknownOperation);
    assert_eq!(
        outcome.denied(),
        [
            "rest:orders:GET /api/missing",
            "rest:billing:GET /api/orders/{}"
        ]
    );
    assert_eq!(
        outcome.policy_version(),
        Some(seeded_policy_epoch().version())
    );
}

#[tokio::test]
async fn a_reserved_key_is_accepted_and_decided_by_the_policy() {
    let service = service_over(tokens(), repository(None));

    let outcome = decide(&service, "valid", &keys_check(&["iam:validate:*"])).await;

    assert_eq!(outcome.reason(), DecisionReason::PermissionMissing);
    assert_eq!(outcome.denied(), ["iam:validate:*"]);
}

#[tokio::test]
async fn a_malformed_path_is_a_malformed_operation() {
    let service = service_over(tokens(), repository(None));

    let outcome = decide(&service, "valid", &rest_check("/api/../orders")).await;

    assert_eq!(outcome.reason(), DecisionReason::MalformedOperation);
}

#[rstest]
#[case::the_token_repository_fails(service_over(FakeTokenRepository::failing(), repository(None)))]
#[case::the_catalogue_loader_fails(service_over(tokens(), FakePolicyReadRepository::failing()))]
#[case::the_policy_read_fails(
    service_over(tokens(), SubjectReadFailing(FakePolicyReadRepository::new().with_catalog(catalog())))
)]
#[tokio::test]
async fn a_failing_dependency_denies_with_unavailable_and_never_allows(
    #[case] service: AccessDecisionService,
) {
    for check in [
        rest_check("/api/orders/42"),
        keys_check(&["rest:orders:GET /api/orders/{}"]),
        keys_check(&["iam:validate:*"]),
    ] {
        let outcome = decide(&service, "valid", &check).await;

        assert_eq!(outcome.decision(), Decision::Deny);
        assert_eq!(outcome.reason(), DecisionReason::Unavailable);
        assert!(outcome.scopes().is_empty());
    }
}

#[tokio::test]
async fn a_failing_dependency_keeps_the_subject_it_already_resolved() {
    let policy = SubjectReadFailing(FakePolicyReadRepository::new().with_catalog(catalog()));
    let service = service_over(tokens(), policy);

    let outcome = decide(&service, "valid", &rest_check("/api/orders/42")).await;

    assert_eq!(outcome.subject(), Some(&user()));
    assert_eq!(outcome.policy_version(), None);
}

#[tokio::test]
async fn the_unavailable_outcome_is_a_deny_with_a_new_identifier_and_no_facts() {
    let service = service_over(tokens(), repository(None));

    let first = service.unavailable();
    let second = service.unavailable();

    assert_eq!(first.decision(), Decision::Deny);
    assert_eq!(first.reason(), DecisionReason::Unavailable);
    assert_eq!(first.denied(), Vec::<String>::new());
    assert_eq!(first.subject(), None);
    assert_eq!(first.policy_version(), None);
    assert_ne!(first.decision_id(), second.decision_id());
}
