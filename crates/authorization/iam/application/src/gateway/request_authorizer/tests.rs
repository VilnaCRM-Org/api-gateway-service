use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueEntryState, CompiledRoleSet, DecisionReason,
    GrantStatus, HttpMethod, NormalizedPath, PathNormalizer, PermissionGrant, PolicySnapshot,
    PolicyVersion, RoleId, ServiceName,
};
use shared_domain::{CommandBus, Uuid};
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::gateway_snapshot::GatewaySnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::token::FakeTokenRepository;

use super::{Authorization, RequestAuthorizer, RouteRequest};
use crate::access_decision_service::AccessDecisionService;
use crate::command::record_rejected_attempt::RecordRejectedAttemptCommand;
use crate::error::IamError;
use crate::fixtures::{ROLE, USER, principal};
use crate::iam_access_guard::AuthorizationUnavailable;

type Recorded = Arc<Mutex<Vec<RecordRejectedAttemptCommand>>>;

fn version() -> PolicyVersion {
    PolicyVersion::new(7).unwrap()
}

fn entry(key: &str) -> CatalogueEntryState {
    CatalogueEntryState {
        key: key.to_owned(),
        sensitive: false,
        audit_always: false,
    }
}

/// A snapshot where the user of the fixtures holds `grants` globally.
fn snapshot_with(grants: &[&str], catalogues: &[(&str, &[&str])]) -> Arc<dyn PolicySnapshot> {
    let role = RoleId::parse(ROLE).unwrap();
    let set = CompiledRoleSet::compile(
        grants
            .iter()
            .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    let mut snapshot = GatewaySnapshot::at(version())
        .with_assignments(
            iam_domain::SubjectRef::user(Uuid::parse(USER).unwrap()),
            vec![AssignmentState {
                role,
                scope: AssignmentScope::Global,
                expires_at_micros: None,
            }],
        )
        .with_role_set(role, set);
    for (service, keys) in catalogues {
        let entries = keys.iter().map(|key| entry(key)).collect();
        snapshot = snapshot.with_catalogue(ServiceName::new(service).unwrap(), entries);
    }
    Arc::new(snapshot)
}

fn authorizer() -> (RequestAuthorizer, Recorded) {
    let recorded: Recorded = Arc::default();
    let sink = Arc::clone(&recorded);
    let commands: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::handling::<
        RecordRejectedAttemptCommand,
        _,
    >(move |command| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        Ok::<(), IamError>(())
    }));
    let authorizer = RequestAuthorizer::new(
        Arc::new(FakeTokenRepository::new()),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
        commands,
    );
    (authorizer, recorded)
}

fn path(raw: &str) -> NormalizedPath {
    PathNormalizer::normalize(raw).unwrap()
}

async fn authorize(
    authorizer: &RequestAuthorizer,
    snapshot: &Arc<dyn PolicySnapshot>,
    service: &str,
    method: HttpMethod,
    raw_path: &str,
) -> Authorization {
    let service = ServiceName::new(service).unwrap();
    let path = path(raw_path);
    let request = RouteRequest {
        snapshot,
        service: &service,
        method,
        path: &path,
        request_id: Some("req-1"),
    };
    authorizer.authorize(&request, &principal()).await
}

#[tokio::test]
async fn a_subject_holding_the_key_of_the_operation_is_allowed_at_the_version_of_the_snapshot() {
    let snapshot = snapshot_with(
        &["rest:users:GET /api/users/{}"],
        &[("users", &["rest:users:GET /api/users/{}"])],
    );
    let (authorizer, _recorded) = authorizer();

    let decided = authorize(
        &authorizer,
        &snapshot,
        "users",
        HttpMethod::Get,
        "/api/users/42",
    )
    .await;

    assert_eq!(decided, Authorization::Allowed(version()));
}

#[tokio::test]
async fn a_subject_without_the_key_gets_permission_missing() {
    let snapshot = snapshot_with(&[], &[("users", &["rest:users:GET /api/users/{}"])]);
    let (authorizer, _recorded) = authorizer();

    let decided = authorize(
        &authorizer,
        &snapshot,
        "users",
        HttpMethod::Get,
        "/api/users/42",
    )
    .await;

    assert_eq!(
        decided,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn an_operation_unknown_to_the_service_is_refused_the_same_way_whether_or_not_another_service_has_it()
 {
    let with_other = snapshot_with(
        &["rest:orders:GET /api/orders"],
        &[
            ("users", &["rest:users:GET /api/users/{}"]),
            ("orders", &["rest:orders:GET /api/orders"]),
        ],
    );
    let without_other = snapshot_with(&[], &[("users", &["rest:users:GET /api/users/{}"])]);
    let (authorizer, _recorded) = authorizer();

    let shared = authorize(
        &authorizer,
        &with_other,
        "users",
        HttpMethod::Get,
        "/api/orders",
    )
    .await;
    let alone = authorize(
        &authorizer,
        &without_other,
        "users",
        HttpMethod::Get,
        "/api/orders",
    )
    .await;

    assert_eq!(
        shared,
        Authorization::Denied(DecisionReason::UnknownOperation)
    );
    assert_eq!(shared, alone);
}

#[tokio::test]
async fn a_service_without_a_catalogue_is_an_unknown_service() {
    let snapshot = snapshot_with(&[], &[]);
    let (authorizer, _recorded) = authorizer();

    let decided = authorize(
        &authorizer,
        &snapshot,
        "users",
        HttpMethod::Get,
        "/api/users",
    )
    .await;

    assert_eq!(
        decided,
        Authorization::Denied(DecisionReason::UnknownService)
    );
}

#[tokio::test]
async fn an_operation_of_iam_is_decided_by_the_rule_table_on_the_reserved_key_of_its_row() {
    let held = snapshot_with(&["iam:audit:read"], &[]);
    let missing = snapshot_with(&[], &[]);
    let (authorizer, recorded) = authorizer();

    let allowed = authorize(
        &authorizer,
        &held,
        "iam",
        HttpMethod::Get,
        "/api/session-revocations/s1",
    )
    .await;
    let refused = authorize(
        &authorizer,
        &missing,
        "iam",
        HttpMethod::Get,
        "/api/session-revocations/s1",
    )
    .await;

    assert_eq!(allowed, Authorization::Allowed(version()));
    assert_eq!(
        refused,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
    let recorded = recorded.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded
            .first()
            .and_then(|command| command.request_id.as_ref().map(ToString::to_string)),
        Some("req-1".to_owned())
    );
}

#[tokio::test]
async fn an_operation_of_iam_that_needs_its_catalogue_key_is_decided_on_the_catalogue_of_iam() {
    let catalogues: &[(&str, &[&str])] = &[("iam", &["rest:iam:POST /api/roles"])];
    let held = snapshot_with(&["rest:iam:POST /api/roles"], catalogues);
    let missing = snapshot_with(&[], catalogues);
    let (authorizer, _recorded) = authorizer();

    let allowed = authorize(&authorizer, &held, "iam", HttpMethod::Post, "/api/roles").await;
    let refused = authorize(&authorizer, &missing, "iam", HttpMethod::Post, "/api/roles").await;

    assert_eq!(allowed, Authorization::Allowed(version()));
    assert_eq!(
        refused,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[tokio::test]
async fn an_operation_of_iam_without_a_row_is_refused_and_a_caller_rule_needs_the_wildcard() {
    let snapshot = snapshot_with(&[], &[]);
    let wildcard = snapshot_with(&["iam:validate:*"], &[]);
    let (authorizer, _recorded) = authorizer();

    let unlisted = authorize(
        &authorizer,
        &snapshot,
        "iam",
        HttpMethod::Post,
        "/api/cache-flushes",
    )
    .await;
    let named = authorize(
        &authorizer,
        &snapshot,
        "iam",
        HttpMethod::Post,
        "/api/access-validations",
    )
    .await;
    let wild = authorize(
        &authorizer,
        &wildcard,
        "iam",
        HttpMethod::Post,
        "/api/access-validations",
    )
    .await;

    assert_eq!(
        unlisted,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
    assert_eq!(
        named,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
    assert_eq!(wild, Authorization::Allowed(version()));
}

#[tokio::test]
async fn an_undecidable_outcome_fails_closed() {
    let decisions: AccessDecisionService = {
        let snapshot = snapshot_with(&[], &[]);
        let reads = Arc::new(super::LoadedSnapshotReads::new(snapshot, Arc::default()));
        AccessDecisionService::new(
            Arc::new(FakeTokenRepository::new()),
            crate::service_catalog_loader::ServiceCatalogLoader::new(Arc::<
                super::LoadedSnapshotReads,
            >::clone(&reads)),
            reads,
            Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
            Arc::new(SequenceUuidGenerator::starting_at(1)),
        )
    };

    let unavailable = RequestAuthorizer::authorization_of(&decisions.unavailable(), version());
    let malformed = RequestAuthorizer::authorization_of(&decisions.malformed(), version());
    let guarded_storage = RequestAuthorizer::guarded(
        Err(IamError::Storage(Box::new(AuthorizationUnavailable))),
        version(),
    );
    let guarded_forbidden = RequestAuthorizer::guarded(Err(IamError::Forbidden), version());

    assert_eq!(unavailable, Authorization::Unavailable);
    assert_eq!(
        malformed,
        Authorization::Denied(DecisionReason::MalformedOperation)
    );
    assert_eq!(guarded_storage, Authorization::Unavailable);
    assert_eq!(
        guarded_forbidden,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
}

#[test]
fn the_subject_of_a_service_token_is_the_service_and_that_of_a_user_token_is_the_user() {
    use iam_domain::{
        AccessToken, AccessTokenParts, SubjectId, SubjectRef, TokenId, TokenIdentity,
    };

    use crate::principal::Principal;

    let service = ServiceName::new("billing").unwrap();
    let token = AccessToken::new(AccessTokenParts {
        subject: SubjectId::Service(service.clone()),
        session: None,
        token_id: TokenId::new("jti-service").unwrap(),
        roles: Vec::new(),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_mins(15))
            .unwrap(),
    });
    let caller = Principal::from(TokenIdentity::from(&token));

    assert_eq!(super::subject_of(&caller), SubjectRef::service(service));
    assert_eq!(
        super::subject_of(&principal()),
        SubjectRef::user(Uuid::parse(USER).unwrap())
    );
}

async fn authorize_traced(
    authorizer: &RequestAuthorizer,
    snapshot: &Arc<dyn PolicySnapshot>,
    service: &str,
    raw_path: &str,
) -> super::TracedAuthorization {
    let service = ServiceName::new(service).unwrap();
    let path = path(raw_path);
    let request = RouteRequest {
        snapshot,
        service: &service,
        method: HttpMethod::Get,
        path: &path,
        request_id: Some("req-1"),
    };
    authorizer.authorize_traced(&request, &principal()).await
}

#[tokio::test]
async fn a_traced_allow_names_the_key_and_a_traced_denial_lists_the_denied_key() {
    let (authorizer, _recorded) = authorizer();
    let held = snapshot_with(
        &["rest:users:GET /api/users/{}"],
        &[("users", &["rest:users:GET /api/users/{}"])],
    );
    let missing = snapshot_with(&[], &[("users", &["rest:users:GET /api/users/{}"])]);

    let allowed = authorize_traced(&authorizer, &held, "users", "/api/users/42").await;
    let denied = authorize_traced(&authorizer, &missing, "users", "/api/users/42").await;

    assert_eq!(allowed.authorization, Authorization::Allowed(version()));
    assert_eq!(
        allowed.trace.permission_key.as_deref(),
        Some("rest:users:GET /api/users/{}")
    );
    assert!(!allowed.trace.wildcard);
    assert_eq!(allowed.denied.len(), 0);
    assert_eq!(
        denied.authorization,
        Authorization::Denied(DecisionReason::PermissionMissing)
    );
    assert_eq!(denied.denied, ["rest:users:GET /api/users/{}"]);
}

#[tokio::test]
async fn a_traced_allow_through_a_wildcard_grant_is_noted() {
    let (authorizer, _recorded) = authorizer();
    let snapshot = snapshot_with(
        &["rest:users:*"],
        &[("users", &["rest:users:GET /api/users/{}"])],
    );

    let traced = authorize_traced(&authorizer, &snapshot, "users", "/api/users/42").await;

    assert_eq!(traced.authorization, Authorization::Allowed(version()));
    assert!(traced.trace.wildcard);
}
