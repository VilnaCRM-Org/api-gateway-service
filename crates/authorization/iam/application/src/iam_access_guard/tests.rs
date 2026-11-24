use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    AccessToken, AccessTokenParts, AssignmentScope, AuditOutcome, CompiledRoleSet, GrantStatus,
    GraphQlSchemaParser as _, HttpMethod, PathTemplate, PermissionFlags, PermissionGrant,
    PolicyReadRepository, RepositoryError, RestOperation, RestOperationSet, RoleAssignment, RoleId,
    ServiceCatalog, ServiceName, SessionId, SubjectId, SubjectPolicy, SubjectRef, TokenId,
    TokenIdentity,
};
use rstest::rstest;
use shared_domain::{CommandHandler as _, Uuid};
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::token::FakeTokenRepository;

use super::{GraphQlOperationRequest, IamAccessGuard, OperationRequest, Verdict};
use crate::access_decision_service::AccessDecisionService;
use crate::command::record_rejected_attempt::{
    RecordRejectedAttemptCommand, RecordRejectedAttemptCommandHandler,
};
use crate::error::IamError;
use crate::graphql::AsyncGraphQlSchemaParser;
use crate::operation_rules::{OperationRule, Requirement};
use crate::principal::Principal;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::rejected_attempt_writer::RejectedAttemptWriter;
use crate::service_catalog_loader::ServiceCatalogLoader;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const NOW: u64 = 1_800_000_000;
const ROLES: &str = "/api/roles";
const IAM_SDL: &str = "type Query { roles: String } type Mutation { createRole: String }";

type Recorded = Arc<Mutex<Vec<RecordRejectedAttemptCommand>>>;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(USER).unwrap())
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    })))
}

/// The catalogue of service `iam` with the operations the tests call.
fn catalog() -> ServiceCatalog {
    let mut operations = RestOperationSet::new();
    for (method, template) in [
        (HttpMethod::Post, ROLES),
        (HttpMethod::Get, "/api/roles/{id}"),
        (HttpMethod::Post, "/api/access-validations"),
    ] {
        operations
            .insert(RestOperation {
                method,
                template: PathTemplate::from_openapi_path(template).unwrap(),
                label: None,
                flags: PermissionFlags::NONE,
            })
            .unwrap();
    }
    let graph = AsyncGraphQlSchemaParser.parse(IAM_SDL).unwrap();
    ServiceCatalog::new(
        ServiceName::iam().clone(),
        seeded_policy_epoch(),
        vec![operations],
        vec![graph],
    )
}

fn holding(grants: &[&str]) -> SubjectPolicy {
    let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
    let grants = grants
        .iter()
        .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active));
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role, AssignmentScope::Global, None)],
        BTreeMap::from([(role, CompiledRoleSet::compile(grants))]),
    )
}

fn repository(grants: &[&str]) -> FakePolicyReadRepository {
    FakePolicyReadRepository::new()
        .with_catalog(catalog())
        .with_subject(user(), holding(grants))
}

fn guard_over(policy: impl PolicyReadRepository + 'static) -> (IamAccessGuard, Recorded) {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(policy);
    let decisions = AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let recorded: Recorded = Arc::default();
    let sink = Arc::clone(&recorded);
    let bus = FakeCommandBus::handling::<RecordRejectedAttemptCommand, _>(move |command| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        Ok::<(), IamError>(())
    });
    (
        IamAccessGuard::new(Arc::new(decisions), Arc::new(bus)),
        recorded,
    )
}

const fn request<'a>(method: &'a str, template: &'a str, path: &'a str) -> OperationRequest<'a> {
    OperationRequest {
        method,
        template,
        path,
        request_id: Some("req-1"),
    }
}

fn refusals(recorded: &Recorded) -> Vec<RecordRejectedAttemptCommand> {
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[tokio::test]
async fn a_caller_holding_the_catalogue_key_passes_and_nothing_is_recorded() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:POST /api/roles"]));

    let outcome = guard
        .authorize(&principal(), &request("POST", ROLES, ROLES))
        .await;

    assert!(outcome.is_ok());
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_templated_operation_is_matched_on_the_concrete_path() {
    let (guard, _recorded) = guard_over(repository(&["rest:iam:GET /api/roles/{}"]));
    let path = "/api/roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab";

    let outcome = guard
        .authorize(&principal(), &request("GET", "/api/roles/{id}", path))
        .await;

    assert!(outcome.is_ok());
}

#[tokio::test]
async fn a_caller_without_the_catalogue_key_is_forbidden_and_the_refusal_is_offered() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:GET /api/roles/{}"]));

    let outcome = guard
        .authorize(&principal(), &request("POST", ROLES, ROLES))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    let offered = refusals(&recorded);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].actor.to_string(), format!("user:{USER}"));
    assert_eq!(offered[0].action.as_str(), "role.create");
    assert_eq!(offered[0].reason.as_str(), "forbidden");
    assert_eq!(offered[0].target.target_type(), "operation");
    assert_eq!(offered[0].target.target_id(), "role.create");
    assert_eq!(
        offered[0]
            .request_id
            .as_ref()
            .map(iam_domain::RequestId::as_str),
        Some("req-1")
    );
}

#[tokio::test]
async fn a_refusal_reaches_the_audit_log_in_the_next_flush_as_a_rejected_record() {
    let (guard, recorded) = guard_over(repository(&[]));
    let outcome = guard
        .authorize(&principal(), &request("POST", ROLES, ROLES))
        .await;
    assert!(matches!(outcome, Err(IamError::Forbidden)));
    let log = Arc::new(FakeRejectedAttemptLog::new());
    let handler = RecordRejectedAttemptCommandHandler::new(
        Arc::<FakeRejectedAttemptLog>::clone(&log),
        Arc::new(FixedClock::at(at(NOW))),
    );
    for command in refusals(&recorded) {
        handler.handle(command).await.unwrap();
    }
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let writer = RejectedAttemptWriter::new(
        log,
        Arc::<FakeSecurityAuditLog>::clone(&audit),
        Arc::new(FixedClock::at(at(NOW + 1))),
        Arc::new(SequenceUuidGenerator::starting_at(100)),
    );

    writer.flush().await;

    let stored = audit.recorded();
    assert_eq!(stored.len(), 1);
    let parts = stored[0].event().parts();
    assert_eq!(parts.outcome, AuditOutcome::Rejected);
    assert_eq!(parts.actor.to_string(), format!("user:{USER}"));
    assert_eq!(parts.action.as_str(), "role.create");
}

#[tokio::test]
async fn a_caller_holding_only_the_reserved_validate_key_is_admitted_to_validation() {
    let (guard, recorded) = guard_over(repository(&["iam:validate:*"]));
    let path = "/api/access-validations";

    let outcome = guard
        .authorize(&principal(), &request("POST", path, path))
        .await;

    assert!(outcome.is_ok());
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn validation_needs_no_catalogue_of_service_iam() {
    let bare = FakePolicyReadRepository::new().with_subject(user(), holding(&["iam:validate:*"]));
    let (guard, _recorded) = guard_over(bare);
    let path = "/api/token-resolutions";

    let outcome = guard
        .authorize(&principal(), &request("POST", path, path))
        .await;

    assert!(outcome.is_ok());
}

#[rstest]
#[case::the_catalogue_key_only(&["rest:iam:POST /api/access-validations"])]
#[case::another_service_scope(&["iam:validate:core"])]
#[case::an_unrelated_reserved_key(&["iam:audit:read"])]
#[tokio::test]
async fn validation_is_refused_without_the_reserved_key(#[case] grants: &[&str]) {
    let (guard, recorded) = guard_over(repository(grants));
    let path = "/api/access-validations";

    let outcome = guard
        .authorize(&principal(), &request("POST", path, path))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    assert_eq!(refusals(&recorded)[0].action.as_str(), "access.validate");
}

#[tokio::test]
async fn an_operation_missing_from_the_table_is_refused_and_audited() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:*", "iam:validate:*"]));

    let outcome = guard
        .authorize(
            &principal(),
            &request("POST", "/api/cache-flushes", "/api/cache-flushes"),
        )
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    let offered = refusals(&recorded);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].action.as_str(), "operation.unlisted");
    assert_eq!(offered[0].reason.as_str(), "operation_unlisted");
    assert_eq!(offered[0].target.target_id(), "/api/cache-flushes");
}

#[tokio::test]
async fn a_caller_without_any_assignment_is_forbidden() {
    let policy = FakePolicyReadRepository::new().with_catalog(catalog());
    let (guard, recorded) = guard_over(policy);

    let outcome = guard
        .authorize(&principal(), &request("POST", ROLES, ROLES))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)), "{outcome:?}");
    assert_eq!(refusals(&recorded).len(), 1);
}

/// A policy repository whose reads all fail.
#[derive(Debug)]
struct Failing;

#[async_trait]
impl PolicyReadRepository for Failing {
    async fn read_subject_policy(
        &self,
        _subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        Err(RepositoryError::Unavailable("policy read failed".into()))
    }

    async fn read_service_catalog(
        &self,
        _service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        Err(RepositoryError::Unavailable("catalogue read failed".into()))
    }
}

#[rstest]
#[case::catalogue_row("POST", ROLES)]
#[case::reserved_row("POST", "/api/access-validations")]
#[tokio::test]
async fn an_unreadable_policy_fails_closed_without_an_audit_record(
    #[case] method: &str,
    #[case] template: &str,
) {
    let (guard, recorded) = guard_over(Failing);

    let outcome = guard
        .authorize(&principal(), &request(method, template, template))
        .await;

    assert!(matches!(outcome, Err(IamError::Storage(_))), "{outcome:?}");
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_failing_bus_does_not_change_the_refusal() {
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(repository(&[]));
    let decisions = AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let guard = IamAccessGuard::new(
        Arc::new(decisions),
        Arc::new(FakeCommandBus::unregistered()),
    );

    let outcome = guard
        .authorize(&principal(), &request("POST", ROLES, ROLES))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
}

#[tokio::test]
async fn a_request_id_that_is_not_visible_ascii_is_dropped_from_the_record() {
    let (guard, recorded) = guard_over(repository(&[]));
    let mut asked = request("POST", ROLES, ROLES);
    asked.request_id = Some("has space");

    let outcome = guard.authorize(&principal(), &asked).await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    assert!(refusals(&recorded)[0].request_id.is_none());
}

#[tokio::test]
async fn a_service_caller_is_decided_as_its_service_subject() {
    let service = ServiceName::new("billing").unwrap();
    let caller = Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::Service(service.clone()),
        session: None,
        token_id: TokenId::new("jti-2").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    })));
    let policy = FakePolicyReadRepository::new()
        .with_catalog(catalog())
        .with_subject(
            SubjectRef::service(service),
            holding(&["rest:iam:POST /api/roles"]),
        );
    let (guard, recorded) = guard_over(policy);

    let outcome = guard
        .authorize(&caller, &request("POST", ROLES, ROLES))
        .await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(refusals(&recorded).len(), 0);
}

#[tokio::test]
async fn a_refusal_that_cannot_be_described_is_not_offered_and_still_refused() {
    let (guard, recorded) = guard_over(repository(&["rest:iam:*"]));
    let template = "/api/caf\u{e9}";

    let outcome = guard
        .authorize(&principal(), &request("POST", template, template))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    assert_eq!(refusals(&recorded).len(), 0);
}

#[tokio::test]
async fn a_row_whose_reserved_key_does_not_parse_is_undecidable() {
    let (guard, _recorded) = guard_over(repository(&["iam:validate:*"]));
    let rule = OperationRule {
        method: HttpMethod::Post,
        template: "/api/defect",
        action: "defect.call",
        requirement: Requirement::Reserved(&["not a key"]),
    };

    let verdict = guard.reserved_verdict(user(), rule.requirement).await;

    assert_eq!(verdict, Verdict::Unavailable);
}

fn fields(coordinates: &[String]) -> GraphQlOperationRequest<'_> {
    GraphQlOperationRequest {
        coordinates,
        request_id: Some("req-1"),
    }
}

fn selected(coordinates: &[&str]) -> Vec<String> {
    coordinates.iter().map(|name| (*name).to_owned()).collect()
}

#[tokio::test]
async fn a_caller_holding_the_field_keys_passes_a_graphql_document() {
    let (guard, recorded) = guard_over(repository(&[
        "gql:iam:Query.roles",
        "gql:iam:Mutation.createRole",
    ]));
    let coordinates = selected(&["Query.roles", "Mutation.createRole"]);

    let outcome = guard
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(refusals(&recorded).is_empty());
}

#[tokio::test]
async fn a_caller_lacking_one_field_key_is_forbidden_and_the_refusal_is_audited() {
    let (guard, recorded) = guard_over(repository(&["gql:iam:Query.roles"]));
    let coordinates = selected(&["Query.roles", "Mutation.createRole"]);

    let outcome = guard
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    let offered = refusals(&recorded);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].action.as_str(), "role.create");
    assert_eq!(offered[0].reason.as_str(), "forbidden");
    assert_eq!(offered[0].target.target_id(), "role.create");
}

#[tokio::test]
async fn a_wildcard_grant_covers_the_graphql_fields_of_iam() {
    let (guard, _recorded) = guard_over(repository(&["gql:iam:*"]));
    let coordinates = selected(&["Query.roles"]);

    let outcome = guard
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn graphql_validation_needs_the_reserved_key_and_no_catalogue_key() {
    let (allowed, _recorded) = guard_over(repository(&["iam:validate:*"]));
    let (refused, recorded) = guard_over(repository(&["gql:iam:*"]));
    let coordinates = selected(&["Query.validateAccess"]);

    let passed = allowed
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;
    let denied = refused
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(passed.is_ok(), "{passed:?}");
    assert!(matches!(denied, Err(IamError::Forbidden)));
    assert_eq!(refusals(&recorded)[0].action.as_str(), "access.validate");
}

#[tokio::test]
async fn a_graphql_coordinate_without_a_row_is_refused_and_audited() {
    let (guard, recorded) = guard_over(repository(&["gql:iam:*"]));
    let coordinates = selected(&["Query.cacheFlush"]);

    let outcome = guard
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(matches!(outcome, Err(IamError::Forbidden)));
    let offered = refusals(&recorded);
    assert_eq!(offered[0].action.as_str(), "operation.unlisted");
    assert_eq!(offered[0].target.target_id(), "Query.cacheFlush");
}

#[tokio::test]
async fn an_unreadable_policy_fails_a_graphql_document_closed() {
    let (guard, recorded) = guard_over(Failing);
    let coordinates = selected(&["Query.roles"]);

    let outcome = guard
        .authorize_graphql(&principal(), &fields(&coordinates))
        .await;

    assert!(matches!(outcome, Err(IamError::Storage(_))), "{outcome:?}");
    assert!(refusals(&recorded).is_empty());
}

#[test]
fn a_check_that_cannot_be_built_is_undecidable() {
    let error = super::undecidable(iam_domain::InvalidAccessCheck::PermissionCount);

    assert!(matches!(error, IamError::Storage(_)));
}
