use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, RevocationRepository,
    RevocationSource, SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts,
    SecurityAuditLog, SystemComponent,
};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::revocation::FakeRevocationRepository;
use test_support::security_audit::FakeSecurityAuditLog;

use super::{GetUserTokenCutoffQuery, GetUserTokenCutoffQueryHandler};
use crate::error::IamError;
use crate::revocation_read_fixtures::{OTHER_USER, at, operator, user, user_cutoff, uuid};

fn handler_over(
    repository: &Arc<FakeRevocationRepository>,
    audit: &Arc<FakeSecurityAuditLog>,
) -> GetUserTokenCutoffQueryHandler {
    let revocations: Arc<dyn RevocationRepository> =
        Arc::<FakeRevocationRepository>::clone(repository);
    let log: Arc<dyn SecurityAuditLog> = Arc::<FakeSecurityAuditLog>::clone(audit);
    GetUserTokenCutoffQueryHandler::new(revocations, log)
}

fn query() -> GetUserTokenCutoffQuery {
    GetUserTokenCutoffQuery { user: user() }
}

fn cutoff_record(
    n: u64,
    actor: ActorRef,
    outcome: AuditOutcome,
    action: &str,
) -> SecurityAuditEvent {
    SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::from_uuid(uuid(n)),
        occurred_at: at(n),
        actor,
        caller_service: None,
        action: AuditAction::new(action).unwrap(),
        target: AuditTarget::new("user", &user().to_string()).unwrap(),
        scope: None,
        before: None,
        after: Some(AuditSummary::new("user cut-off set").unwrap()),
        idempotency_key: None,
        outcome,
        reason: None,
        policy_version: None,
        request_id: None,
    })
    .unwrap()
}

async fn operator_cutoff() -> (Arc<FakeRevocationRepository>, Arc<FakeSecurityAuditLog>) {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository
        .set_user_cutoff(&user_cutoff(RevocationSource::Operator))
        .await
        .unwrap();
    (repository, Arc::new(FakeSecurityAuditLog::new()))
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetUserTokenCutoffQuery::NAME, "GetUserTokenCutoffQuery");
}

#[tokio::test]
async fn a_user_without_a_cutoff_is_none() {
    let repository = Arc::new(FakeRevocationRepository::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());

    let answer = handler_over(&repository, &audit)
        .handle(query())
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn the_actor_of_an_operator_cutoff_is_the_actor_of_its_newest_committed_record() {
    let (repository, audit) = operator_cutoff().await;
    let other = ActorRef::System(SystemComponent::Bootstrap);
    for event in [
        cutoff_record(1, other, AuditOutcome::Committed, "user_tokens.cut_off"),
        cutoff_record(
            2,
            operator(),
            AuditOutcome::Committed,
            "user_tokens.cut_off",
        ),
        cutoff_record(
            3,
            ActorRef::System(SystemComponent::Startup),
            AuditOutcome::Rejected,
            "user_tokens.cut_off",
        ),
        cutoff_record(
            4,
            ActorRef::System(SystemComponent::Startup),
            AuditOutcome::Committed,
            "session.revoke",
        ),
    ] {
        audit.append_batch(&[event]).await.unwrap();
    }

    let view = handler_over(&repository, &audit)
        .handle(query())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(view.cutoff, user_cutoff(RevocationSource::Operator));
    assert_eq!(view.actor, Some(operator()));
}

#[tokio::test]
async fn an_operator_cutoff_without_an_audit_record_has_no_actor() {
    let (repository, audit) = operator_cutoff().await;

    let view = handler_over(&repository, &audit)
        .handle(query())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(view.actor, None);
}

#[tokio::test]
async fn a_user_service_cutoff_names_the_user_service_actor_without_reading_the_log() {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository
        .set_user_cutoff(&user_cutoff(RevocationSource::UserService))
        .await
        .unwrap();
    let audit = Arc::new(FakeSecurityAuditLog::new());
    audit
        .append_batch(&[cutoff_record(
            1,
            operator(),
            AuditOutcome::Committed,
            "user_tokens.cut_off",
        )])
        .await
        .unwrap();

    let view = handler_over(&repository, &audit)
        .handle(query())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        view.actor,
        Some(ActorRef::System(SystemComponent::UserService))
    );
}

#[tokio::test]
async fn a_cutoff_of_another_user_is_not_returned() {
    let (repository, audit) = operator_cutoff().await;

    let answer = handler_over(&repository, &audit)
        .handle(GetUserTokenCutoffQuery {
            user: shared_domain::Uuid::parse(OTHER_USER).unwrap(),
        })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let (repository, audit) = operator_cutoff().await;
    repository.fail(true);

    let error = handler_over(&repository, &audit)
        .handle(query())
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
